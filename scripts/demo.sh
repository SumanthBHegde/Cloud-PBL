#!/usr/bin/env bash
#==============================================================================
# Cloud PBL - Data Leak Detection - ONE-COMMAND MANUAL DEMO
#
# The attacker scripts in demos/ only GENERATE suspicious activity. Detection +
# alerting normally happen automatically in the cloud: the DataLeakDetector
# Lambda runs the 6 SQL rules on an EventBridge schedule and emails on a match.
#
# That schedule is DISABLED by default (it re-alerts on old logs every minute).
# THIS script is the manual fallback for a demo without enabling the schedule:
#
#   1. Launch the attacker scenarios (generate the activity)         [demos/]
#   2. Manually invoke the DataLeakDetector Lambda (the trigger)     [detection]
#   3. It runs the 6 rules and sends the SNS alert email on a match.
#
# Usage:
#   ./demo.sh                # run all attacker scenarios, then trigger detection
#   ./demo.sh --skip-attacks # just trigger detection on the existing logs
#==============================================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEMOS_DIR="$SCRIPT_DIR/demos"
STATE_FILE="$PROJECT_ROOT/pbl-state.env"

if [ ! -f "$STATE_FILE" ]; then
  echo "ERROR: $STATE_FILE not found. Run scripts/setup.sh first."
  exit 1
fi
# shellcheck disable=SC1090
source "$STATE_FILE"

SKIP_ATTACKS=0
[ "${1:-}" = "--skip-attacks" ] && SKIP_ATTACKS=1

step() { echo; echo "=============================================================="; echo " $*"; echo "=============================================================="; }

#------------------------------------------------------------------------------
# 1. Launch the attacker scenarios (generate suspicious activity)
#------------------------------------------------------------------------------
if [ "$SKIP_ATTACKS" = "0" ]; then
  step "[1] Launching attacker scenarios (generating suspicious activity)"
  if [ -x "$DEMOS_DIR/run-all-demos.sh" ]; then
    bash "$DEMOS_DIR/run-all-demos.sh"
  else
    echo "ERROR: $DEMOS_DIR/run-all-demos.sh not found."
    exit 1
  fi
  echo
  echo ">>> NOTE: CloudTrail delivers logs to S3 with a 5-15 minute lag, so the"
  echo "    activity just generated may not be visible to the detector yet. The"
  echo "    detection below still catches any already-delivered activity."
else
  step "[1] Skipping attacks (--skip-attacks) - triggering detection only"
fi

#------------------------------------------------------------------------------
# 2. Manually trigger detection (fallback for the disabled EventBridge schedule)
#------------------------------------------------------------------------------
step "[2] Manually invoking the DataLeakDetector Lambda"

if [ -z "${DETECTOR_NAME:-}" ]; then
  echo "ERROR: DETECTOR_NAME not in $STATE_FILE."
  echo "Deploy the detector first:  ./scripts/setup-automation.sh"
  exit 1
fi

echo ">>> Running the 6 SQL detection rules via $DETECTOR_NAME ..."
OUT_FILE="$PROJECT_ROOT/.demo-detector-out.json"
if aws lambda invoke --region "$REGION" --function-name "$DETECTOR_NAME" "$OUT_FILE" \
     --query 'StatusCode' --output text >/dev/null 2>&1; then
  echo "Detector response:"
  cat "$OUT_FILE"; echo
  rm -f "$OUT_FILE"
else
  echo "ERROR: could not invoke $DETECTOR_NAME (is the automation layer deployed?)."
  rm -f "$OUT_FILE"
  exit 1
fi

step "DEMO COMPLETE"
echo " If a rule matched, the detector published an alert to the SNS topic."
echo " Check the inbox subscribed to: $SNS_TOPIC_ARN"
echo " (The subscription must be confirmed to receive the email.)"
