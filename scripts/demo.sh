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
#   ./demo.sh                    # run all attacker scenarios, then trigger detection (all rules)
#   ./demo.sh --skip-attacks     # just trigger detection on the existing logs (all rules)
#   ./demo.sh --case <name>      # trigger ONLY one case, e.g. --case region
#                                # (skips the attackers; runs just that one rule)
#
# Case names (case-insensitive substring): frequency, off-hours, region,
# policy, failed, bulk.  Use --case so running a demo alerts on ONLY that case.
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

# --- args -------------------------------------------------------------------
SKIP_ATTACKS=0
CASE_FILTER=""
case "${1:-}" in
  --skip-attacks) SKIP_ATTACKS=1 ;;
  --case)         SKIP_ATTACKS=1; CASE_FILTER="${2:-}" ;;
esac
if [ "${1:-}" = "--case" ] && [ -z "$CASE_FILTER" ]; then
  echo "ERROR: --case needs a name, e.g. ./demo.sh --case region"
  exit 1
fi

# 1. Launch the attacker scenarios (generate suspicious activity)
if [ "$SKIP_ATTACKS" = "0" ]; then
  if [ -x "$DEMOS_DIR/run-all-demos.sh" ]; then
    bash "$DEMOS_DIR/run-all-demos.sh"
  else
    echo "ERROR: $DEMOS_DIR/run-all-demos.sh not found."
    exit 1
  fi
fi

# 2. Trigger detection (fallback for the disabled EventBridge schedule)
if [ -z "${DETECTOR_NAME:-}" ]; then
  echo "ERROR: DETECTOR_NAME not in $STATE_FILE. Run ./scripts/setup-automation.sh"
  exit 1
fi

OUT_FILE="$PROJECT_ROOT/.demo-detector-out.json"
if [ -n "$CASE_FILTER" ]; then
  aws lambda invoke --region "$REGION" --function-name "$DETECTOR_NAME" \
    --cli-binary-format raw-in-base64-out --payload "{\"rule\":\"$CASE_FILTER\"}" \
    "$OUT_FILE" --query 'StatusCode' --output text >/dev/null
else
  aws lambda invoke --region "$REGION" --function-name "$DETECTOR_NAME" "$OUT_FILE" \
    --query 'StatusCode' --output text >/dev/null
fi
cat "$OUT_FILE"; echo
rm -f "$OUT_FILE"
