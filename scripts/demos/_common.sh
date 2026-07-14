#!/usr/bin/env bash
#==============================================================================
# Cloud PBL - Data Leak Detection - shared helpers for the ATTACKER demos
#
# Every demo-N-*.sh script sources this file. Each demo only *simulates an
# attack* (generates suspicious activity). Detection + alerting happen
# automatically in the cloud via the DataLeakDetector Lambda (EventBridge),
# so the demos here do NOT run any SQL themselves.
#
# This file:
#   - loads resource IDs from ../../pbl-state.env (written by setup.sh)
#   - provides pretty banners
#   - provides the CloudTrail-delivery-lag reminder
#   - provides detected_note() - the "you'll be caught automatically" message
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
  warn "after the activity happens. The cloud detector can only 'see' this"
  warn "attack once the log file lands in the bucket, so the alert email may"
  warn "arrive a few minutes after this attack runs."
}

# --- the "you will be caught automatically" closing note ---------------------
# usage: detected_note "Rule name that catches this attack"
detected_note() {
  local rule_name="$1"
  echo
  echo ">>> ATTACK LAUNCHED. No human runs any SQL here."
  echo "    The cloud DataLeakDetector Lambda runs all 6 SQL rules automatically"
  echo "    (EventBridge schedule) and will flag this under: '$rule_name'."
  echo "    If the schedule is enabled, an SNS alert email is sent on the match."
}
