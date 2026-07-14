#!/usr/bin/env bash
#==============================================================================
# Cloud PBL - Data Leak Monitoring - AUTOMATION LAYER SETUP
#
# Implements the automation layer from SQL_Data_Leak_Detection_AWS.pptx
# (slides 11-14): a scheduled detector that runs the Athena hunt queries
# every 15 minutes and emails an SNS alert ONLY when a rule is triggered.
#
# Creates (on top of an existing setup.sh stack):
#   - IAM role for the detector Lambda (Athena + S3 + SNS + CloudWatch logs)
#   - Lambda "DataLeakDetector" that runs 6 detection queries and alerts on hits
#   - EventBridge (scheduler) rule "DataLeakDetectionSchedule" -> rate(15 minutes)
#
# Reads ./pbl-state.env (from setup.sh) and APPENDS the new resource IDs to it
# so teardown.sh can clean them up.
#
# Usage:
#   chmod +x setup-automation.sh
#   ./setup-automation.sh
#==============================================================================
set -euo pipefail

STATE_FILE="./pbl-state.env"
if [ ! -f "$STATE_FILE" ]; then
  echo "ERROR: $STATE_FILE not found. Run setup.sh first."
  exit 1
fi
# shellcheck disable=SC1090
source "$STATE_FILE"

save() { echo "$1=\"$2\"" >> "$STATE_FILE"; }

# Local temp dir (relative path so the native Windows AWS CLI can read it via fileb://)
TMPDIR_LOCAL="./.pbl-tmp"
mkdir -p "$TMPDIR_LOCAL"
trap 'rm -rf "$TMPDIR_LOCAL"' EXIT

DETECTOR_NAME="DataLeakDetector-${SUFFIX}"
DETECTOR_ROLE_NAME="${DETECTOR_NAME}-role"
SCHEDULE_RULE_NAME="DataLeakDetectionSchedule-${SUFFIX}"
LAMBDA_RUNTIME="python3.12"

echo "=============================================="
echo " Automation layer setup ($REGION)"
echo " Detector Lambda : $DETECTOR_NAME"
echo " Schedule        : rate(15 minutes)"
echo "=============================================="

#------------------------------------------------------------------------------
# 1. IAM role for the detector Lambda
#------------------------------------------------------------------------------
echo
echo ">>> [1] Creating IAM role for detector Lambda ..."
TRUST='{
  "Version":"2012-10-17",
  "Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]
}'
DETECTOR_ROLE_ARN=$(aws iam create-role --role-name "$DETECTOR_ROLE_NAME" \
  --assume-role-policy-document "$TRUST" \
  --query 'Role.Arn' --output text)
save DETECTOR_ROLE_NAME "$DETECTOR_ROLE_NAME"
save DETECTOR_ROLE_ARN  "$DETECTOR_ROLE_ARN"

aws iam attach-role-policy --role-name "$DETECTOR_ROLE_NAME" \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# Inline policy: Athena + Glue (Athena needs Glue catalog) + S3 (log + results) + SNS publish
INLINE_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Athena",
      "Effect": "Allow",
      "Action": [
        "athena:StartQueryExecution",
        "athena:GetQueryExecution",
        "athena:GetQueryResults",
        "athena:GetWorkGroup"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GlueCatalog",
      "Effect": "Allow",
      "Action": [
        "glue:GetTable",
        "glue:GetDatabase",
        "glue:GetPartitions"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3LogAndResults",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"],
      "Resource": [
        "arn:aws:s3:::${S3_BUCKET}",
        "arn:aws:s3:::${S3_BUCKET}/*"
      ]
    },
    {
      "Sid": "SNSPublish",
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "${SNS_TOPIC_ARN}"
    }
  ]
}
EOF
)
aws iam put-role-policy --role-name "$DETECTOR_ROLE_NAME" \
  --policy-name "DataLeakDetectorPolicy" \
  --policy-document "$INLINE_POLICY"

echo "    role=$DETECTOR_ROLE_ARN"
echo "    Waiting 15s for IAM propagation ..."
sleep 15

#------------------------------------------------------------------------------
# 2. Detector Lambda code
#------------------------------------------------------------------------------
echo
echo ">>> [2] Packaging detector Lambda code ..."
WORK="$TMPDIR_LOCAL/detector-build"
mkdir -p "$WORK"
cat > "$WORK/lambda_function.py" <<EOF
"""
DataLeakDetector - scheduled every 15 min by EventBridge.

Runs the 6 SQL detection rules from SQL_Data_Leak_Detection_AWS.pptx (slide 12)
against the cloudtrail_logs Athena table, and publishes an SNS alert ONLY when
a rule returns one or more rows (i.e. an anomaly is detected).
"""
import boto3
import time

REGION       = "${REGION}"
DATABASE     = "default"
WORKGROUP    = "primary"
OUTPUT_LOC   = "s3://${S3_BUCKET}/athena-results/"
TOPIC_ARN    = "${SNS_TOPIC_ARN}"

athena = boto3.client("athena", region_name=REGION)
sns    = boto3.client("sns", region_name=REGION)

# Each rule: (name, trigger description, SQL). Queries are written so that
# ANY returned row means the rule fired.
RULES = [
    ("High-Frequency Access", ">50 requests / IP / hour",
     "SELECT sourceIPAddress, COUNT(*) AS access_count "
     "FROM cloudtrail_logs GROUP BY sourceIPAddress HAVING COUNT(*) > 50"),
    ("Off-Hours Access", "activity between 00:00-05:00 UTC",
     "SELECT eventTime, eventSource, eventName, sourceIPAddress "
     "FROM cloudtrail_logs "
     "WHERE hour(from_iso8601_timestamp(eventTime)) BETWEEN 0 AND 5"),
    ("Unknown Region", "API calls from unauthorized regions",
     "SELECT awsRegion, COUNT(*) AS cnt FROM cloudtrail_logs "
     "WHERE awsRegion NOT IN ('${REGION}') GROUP BY awsRegion"),
    ("Policy Modification", "PutBucketPolicy / PutBucketAcl events",
     "SELECT eventTime, eventName, sourceIPAddress, awsRegion "
     "FROM cloudtrail_logs "
     "WHERE eventName IN ('PutBucketPolicy', 'PutBucketAcl')"),
    ("Consecutive Failed Logins", ">=3 ConsoleLogin failures",
     "SELECT sourceIPAddress, COUNT(*) AS fails FROM cloudtrail_logs "
     "WHERE eventName = 'ConsoleLogin' AND errorMessage IS NOT NULL "
     "GROUP BY sourceIPAddress HAVING COUNT(*) >= 3"),
    ("Bulk S3 Download", ">100 GetObject calls",
     "SELECT sourceIPAddress, COUNT(*) AS downloads FROM cloudtrail_logs "
     "WHERE eventName = 'GetObject' GROUP BY sourceIPAddress HAVING COUNT(*) > 100"),
]


def run_query(sql):
    qid = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": DATABASE},
        ResultConfiguration={"OutputLocation": OUTPUT_LOC},
        WorkGroup=WORKGROUP,
    )["QueryExecutionId"]

    # poll up to ~50s for completion
    for _ in range(25):
        state = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(2)

    if state != "SUCCEEDED":
        print(f"  query {state}: {sql[:60]}...")
        return []

    rows = athena.get_query_results(QueryExecutionId=qid)["ResultSet"]["Rows"]
    # row[0] is the header; data rows are everything after it
    return rows[1:]


def lambda_handler(event, context):
    triggered = []

    for name, trigger, sql in RULES:
        try:
            data_rows = run_query(sql)
        except Exception as e:
            print(f"Rule '{name}' query error: {e}")
            continue

        if data_rows:
            # summarise first matching row for the alert body
            first = [c.get("VarCharValue", "") for c in data_rows[0]["Data"]]
            triggered.append({
                "rule": name,
                "trigger": trigger,
                "match_count": len(data_rows),
                "sample": ", ".join(first),
            })

    if not triggered:
        print("No anomalies detected this cycle.")
        return {"statusCode": 200, "body": "No anomalies detected."}

    # Build a structured alert message (slide 13 style)
    lines = [
        "SECURITY ALERT - SUSPICIOUS ACTIVITY DETECTED",
        "=" * 45,
        "",
        f"{len(triggered)} detection rule(s) triggered in the last monitoring cycle:",
        "",
    ]
    for t in triggered:
        lines += [
            f"Rule Triggered : {t['rule']}",
            f"Condition      : {t['trigger']}",
            f"Matches        : {t['match_count']}",
            f"Sample         : {t['sample']}",
            "-" * 45,
        ]
    lines += [
        "",
        "Recommended Action:",
        "  -> Review CloudTrail logs immediately",
        "  -> Block source IP if unauthorized",
        "  -> Check IAM credentials for compromise",
    ]
    message = "\n".join(lines)

    sns.publish(
        TopicArn=TOPIC_ARN,
        Subject="[SECURITY] Data Leak Alert",
        Message=message,
    )
    print(f"Alert published: {len(triggered)} rule(s) triggered.")
    return {"statusCode": 200, "body": f"{len(triggered)} rule(s) triggered; alert sent."}
EOF

( cd "$WORK" && zip -q lambda.zip lambda_function.py )

#------------------------------------------------------------------------------
# 3. Create the detector Lambda
#------------------------------------------------------------------------------
echo
echo ">>> [3] Creating detector Lambda: $DETECTOR_NAME ..."
aws lambda create-function --region "$REGION" \
  --function-name "$DETECTOR_NAME" \
  --runtime "$LAMBDA_RUNTIME" \
  --role "$DETECTOR_ROLE_ARN" \
  --handler lambda_function.lambda_handler \
  --zip-file "fileb://$WORK/lambda.zip" \
  --timeout 120 \
  --memory-size 256 >/dev/null
save DETECTOR_NAME "$DETECTOR_NAME"
DETECTOR_ARN=$(aws lambda get-function --region "$REGION" \
  --function-name "$DETECTOR_NAME" --query 'Configuration.FunctionArn' --output text)
echo "    $DETECTOR_ARN"

#------------------------------------------------------------------------------
# 4. EventBridge schedule -> invoke detector every 15 minutes
#------------------------------------------------------------------------------
echo
echo ">>> [4] Creating EventBridge rule: $SCHEDULE_RULE_NAME (rate 15 min) ..."
RULE_ARN=$(aws events put-rule --region "$REGION" \
  --name "$SCHEDULE_RULE_NAME" \
  --schedule-expression "rate(15 minutes)" \
  --state ENABLED \
  --description "Runs DataLeakDetector every 15 minutes" \
  --query 'RuleArn' --output text)
save SCHEDULE_RULE_NAME "$SCHEDULE_RULE_NAME"

# allow EventBridge to invoke the Lambda
aws lambda add-permission --region "$REGION" \
  --function-name "$DETECTOR_NAME" \
  --statement-id "eventbridge-invoke-${SUFFIX}" \
  --action "lambda:InvokeFunction" \
  --principal events.amazonaws.com \
  --source-arn "$RULE_ARN" >/dev/null

aws events put-targets --region "$REGION" \
  --rule "$SCHEDULE_RULE_NAME" \
  --targets "Id=detector,Arn=$DETECTOR_ARN" >/dev/null
echo "    Rule armed -> $DETECTOR_NAME"

echo
echo "=============================================="
echo " AUTOMATION LAYER READY"
echo "=============================================="
echo " The detector now runs every 15 minutes automatically."
echo " It emails the SNS topic ONLY when a detection rule fires."
echo
echo " Invoke it once now to test:"
echo "   aws lambda invoke --region $REGION --function-name $DETECTOR_NAME out.json && cat out.json"
echo
echo " New resource IDs appended to $STATE_FILE (teardown.sh will remove them)."
