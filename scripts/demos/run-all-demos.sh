#!/usr/bin/env bash
#==============================================================================
# Runs all 6 SQL data-leak detection demos back to back.
#
# Each demo (1) generates the suspicious activity for its case, and
# (2) runs the matching Athena detection query. Because CloudTrail takes
# 5-15 minutes to deliver events to S3, the FIRST pass often shows 0 rows for
# the freshly-generated activity. Recommended flow:
#
#   ./run-all-demos.sh          # pass 1 - generates all the activity
#   ...wait ~10-15 minutes...
#   ./run-all-demos.sh          # pass 2 - queries now return the matches
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
  echo
done

echo "=============================================================="
echo " ALL 6 CASES DEMONSTRATED"
echo " If any query showed 0 rows, wait 10-15 min and re-run this."
echo "=============================================================="
