#!/usr/bin/env bash
#==============================================================================
# Cloud PBL - Data Leak Detection - shared helpers for the per-case demos
#
# Every demo-N-*.sh script sources this file. It:
#   - loads resource IDs from ../pbl-state.env (written by setup.sh)
#   - provides pretty banners
#   - provides run_athena() which runs a detection query and prints the result
#   - provides the CloudTrail-delivery-lag reminder
#
# Not meant to be run directly.
#==============================================================================
set -uo pipefail

# --- locate and load pbl-state.env -------------------------------------------
# Demos live in scripts/demos/ ; the state file is in the project root.
_DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$_DEMO_DIR/../.." && pwd)"
STATE_FILE="$PROJECT_ROOT/pbl-state.env"

if [ ! -f "$STATE_FILE" ]; then
  echo "ERROR: $STATE_FILE not found."
  echo "Run scripts/setup.sh first so the stack (and this state file) exists."
  exit 1
fi
# shellcheck disable=SC1090
source "$STATE_FILE"

# DB connection details (same defaults as setup.sh / demo.sh)
DB_NAME="PBL_DB_${SUFFIX}"
DB_USER="${DB_USER:-admin}"
DB_PASS="${DB_PASS:-Admin12345!}"

# --- pretty output -----------------------------------------------------------
banner() {
  echo
  echo "=============================================================="
  echo " $*"
  echo "=============================================================="
}
info() { echo "    $*"; }
warn() { echo "[!] $*"; }
rule() { echo "--------------------------------------------------------------"; }

lag_note() {
  echo
  warn "CloudTrail delivers events to S3 in batches - usually 5-15 minutes"
  warn "after the activity happens. If the query below returns no rows, wait"
  warn "a few minutes and re-run this same demo script; the activity you just"
  warn "generated will show up once the log file lands in the bucket."
}

# --- run one Athena detection query and print its rows -----------------------
# usage: run_athena "Human label" "SELECT ... FROM cloudtrail_logs ..."
run_athena() {
  local label="$1" query="$2"
  echo
  echo ">>> Detection query: $label"
  rule
  echo "$query"
  rule

  local qid
  qid=$(aws athena start-query-execution --region "$REGION" \
    --query-string "$query" \
    --query-execution-context "Database=default" \
    --result-configuration "OutputLocation=s3://${S3_BUCKET}/athena-results/" \
    --work-group primary \
    --query 'QueryExecutionId' --output text) || { warn "could not start query"; return 1; }

  local status="RUNNING"
  for _ in $(seq 1 25); do
    status=$(aws athena get-query-execution --region "$REGION" \
      --query-execution-id "$qid" \
      --query 'QueryExecution.Status.State' --output text)
    case "$status" in
      SUCCEEDED|FAILED|CANCELLED) break ;;
    esac
    sleep 3
  done

  if [ "$status" != "SUCCEEDED" ]; then
    warn "query $status (id=$qid)"
    warn "CloudTrail logs for this activity may not have landed in S3 yet."
    return 0
  fi

  # rows[0] is the header row; if that's all we got, nothing matched.
  local nrows
  nrows=$(aws athena get-query-results --region "$REGION" --query-execution-id "$qid" \
    --query 'length(ResultSet.Rows)' --output text)

  echo "Result:"
  aws athena get-query-results --region "$REGION" --query-execution-id "$qid" \
    --query 'ResultSet.Rows[].Data[*].VarCharValue' --output table

  if [ "${nrows:-0}" -le 1 ]; then
    echo
    warn "0 matching rows -> rule NOT triggered yet (see the delay note above)."
  else
    echo
    echo ">>> RULE WOULD FIRE: $((nrows - 1)) matching row(s). The DataLeakDetector"
    echo "    Lambda publishes an SNS alert whenever this query returns >= 1 row."
  fi
}

# --- optionally invoke the detector Lambda to send a real alert email --------
invoke_detector_if_present() {
  if [ -n "${DETECTOR_NAME:-}" ]; then
    echo
    echo ">>> Invoking the automated detector Lambda ($DETECTOR_NAME) so it"
    echo "    evaluates all 6 rules now and emails an alert if any fired ..."
    local out="$PROJECT_ROOT/.demo-detector-out.json"
    if aws lambda invoke --region "$REGION" --function-name "$DETECTOR_NAME" "$out" >/dev/null 2>&1; then
      cat "$out"; echo
      rm -f "$out"
    else
      warn "detector Lambda not invocable (run scripts/setup-automation.sh to create it)."
    fi
  else
    info "(Automation layer not deployed - run scripts/setup-automation.sh to get"
    info " the scheduled detector + real alert emails. This demo only shows the query.)"
  fi
}
