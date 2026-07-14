#!/usr/bin/env bash
#==============================================================================
# Cloud PBL - Data Leak Monitoring System - DEMO SCRIPT
#
# Runs the end-to-end demo against an already-deployed stack (see setup.sh):
#   1. Simulate suspicious DB activity (Part E of the PDF)
#   2. Run the Athena hunt queries against the CloudTrail logs (Part F)
#   3. Invoke the Lambda to dispatch the SNS alert email (Part H)
#
# Reads ./pbl-state.env (written by setup.sh) for all resource IDs.
#
# Usage:
#   chmod +x demo.sh
#   ./demo.sh
#==============================================================================
set -uo pipefail

STATE_FILE="./pbl-state.env"
if [ ! -f "$STATE_FILE" ]; then
  echo "ERROR: $STATE_FILE not found. Run setup.sh first."
  exit 1
fi
# shellcheck disable=SC1090
source "$STATE_FILE"

DB_NAME="PBL_DB_${SUFFIX}"
DB_USER="${DB_USER:-admin}"
DB_PASS="${DB_PASS:-Admin12345!}"

step() { echo; echo "=============================================="; echo " $*"; echo "=============================================="; }

#------------------------------------------------------------------------------
# Part E: simulate suspicious activity against RDS
#------------------------------------------------------------------------------
step "[E] Simulating suspicious activity on employee_data"

if ! command -v mysql >/dev/null 2>&1; then
  echo "[skip] mysql client not installed - skipping Part E"
else
  echo ">>> Activity A: massive extraction (3x SELECT *)"
  for i in 1 2 3; do
    mysql -h "$DB_ENDPOINT" -P 3306 -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" \
      -e "SELECT * FROM employee_data;" 2>&1 | grep -v "Warning"
  done

  echo
  echo ">>> Activity B: high-value target discovery"
  mysql -h "$DB_ENDPOINT" -P 3306 -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" \
    -e "SELECT * FROM employee_data WHERE salary >= 100000;
        SELECT email FROM employee_data WHERE department = 'Executive Management';" \
    2>&1 | grep -v "Warning"

  echo
  echo ">>> Activity C: brute-force login attempts (expected to fail)"
  for i in 1 2 3; do
    mysql -h "$DB_ENDPOINT" -P 3306 -u hacker_test -p"wrong_pass_$i" "$DB_NAME" \
      -e "SELECT 1;" 2>&1 | grep -v "Warning"
  done
fi

#------------------------------------------------------------------------------
# Part F: Athena hunt queries
#------------------------------------------------------------------------------
step "[F] Running Athena hunt queries against CloudTrail logs"

run_athena() {
  local label="$1" query="$2"
  echo
  echo ">>> $label"
  local qid
  qid=$(aws athena start-query-execution --region "$REGION" \
    --query-string "$query" \
    --query-execution-context "Database=default" \
    --result-configuration "OutputLocation=s3://${S3_BUCKET}/athena-results/" \
    --work-group primary \
    --query 'QueryExecutionId' --output text)

  local status
  for attempt in $(seq 1 20); do
    status=$(aws athena get-query-execution --region "$REGION" \
      --query-execution-id "$qid" \
      --query 'QueryExecution.Status.State' --output text)
    [ "$status" = "SUCCEEDED" ] || [ "$status" = "FAILED" ] || [ "$status" = "CANCELLED" ] && break
    sleep 3
  done

  if [ "$status" = "SUCCEEDED" ]; then
    aws athena get-query-results --region "$REGION" --query-execution-id "$qid" \
      --query 'ResultSet.Rows[].Data[*].VarCharValue' --output text
  else
    echo "    query $status (id=$qid) - CloudTrail logs may not have landed in S3 yet (can take ~5-15 min)"
  fi
}

run_athena "High-volume source IPs (>50 events)" \
  "SELECT sourceIPAddress, COUNT(*) AS access_count FROM cloudtrail_logs GROUP BY sourceIPAddress HAVING COUNT(*) > 50;"

run_athena "Off-hours activity (00:00-05:00 UTC)" \
  "SELECT eventTime, eventSource, eventName, sourceIPAddress FROM cloudtrail_logs WHERE hour(from_iso8601_timestamp(eventTime)) BETWEEN 0 AND 5;"

run_athena "Bucket policy tampering (PutBucketPolicy)" \
  "SELECT eventTime, eventSource, eventName, sourceIPAddress, awsRegion FROM cloudtrail_logs WHERE eventName = 'PutBucketPolicy';"

#------------------------------------------------------------------------------
# Part H: trigger the alert Lambda
#------------------------------------------------------------------------------
step "[H] Invoking Lambda to dispatch the data-leak alert email"

OUT_FILE="./demo-lambda-out.json"
aws lambda invoke --region "$REGION" --function-name "$LAMBDA_NAME" "$OUT_FILE" >/dev/null
echo "Lambda response:"
cat "$OUT_FILE"
echo
rm -f "$OUT_FILE"

echo
echo "=============================================="
echo " DEMO COMPLETE"
echo "=============================================="
echo " Check the inbox subscribed to the SNS topic for the alert email."
echo " (Subscription must be confirmed - see setup.sh output for the link.)"
