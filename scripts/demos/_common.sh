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
#   - provides pretty banners (banner / info / warn / rule)
#
# Explanations (CloudTrail lag, how automatic detection works, per-case caveats)
# live in scripts/demos/README.md, NOT in these scripts.
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

