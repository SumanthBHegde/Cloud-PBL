#!/usr/bin/env bash
#==============================================================================
# Runs all 6 attacker scenarios back to back.
#
# These scripts are ATTACKERS: each one only GENERATES the suspicious activity
# for its case. They do NOT detect or alert - detection is done in the cloud by
# the DataLeakDetector Lambda (the 6 SQL rules in Athena).
#
# CloudTrail delivers events to S3 with a 5-15 minute lag, so the generated
# activity is not queryable by the detector immediately. Recommended flow:
#
#   ./run-all-demos.sh                       # generate all the activity
#   ...wait ~10-15 minutes for CloudTrail to deliver...
#   ../demo.sh --case <name>                 # trigger ONE case -> one alert
#
# where <name> is one of: frequency, off-hours, region, policy, failed, bulk.
# Or trigger all rules at once with:  ../demo.sh --skip-attacks
#
# Usage:  ./run-all-demos.sh
#==============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for d in \
  "$HERE/demo-1-high-frequency.sh" \
  "$HERE/demo-2-off-hours.sh" \
  "$HERE/demo-3-unknown-region.sh" \
  "$HERE/demo-4-policy-modification.sh" \
  "$HERE/demo-5-failed-logins.sh" \
  "$HERE/demo-6-bulk-download.sh"
do
  bash "$d"
done
