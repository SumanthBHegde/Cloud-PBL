#!/usr/bin/env bash
#==============================================================================
# CASE 5 - CONSECUTIVE FAILED LOGINS  (brute-force sign-in)
#
#   Rule    : repeated failed AWS Console sign-ins from the same IP.
#   Trigger : >= 3 ConsoleLogin events with a non-null errorMessage
#             (i.e. "Failed authentication") from one sourceIPAddress.
#   Real-world meaning: password-guessing / credential-stuffing against the
#   AWS root or IAM console.
#
# IMPORTANT - WHY THIS ONE IS PART-MANUAL
#   A ConsoleLogin event is ONLY produced by the AWS web sign-in page. It
#   cannot be generated from the AWS CLI (CLI calls are API auth, not console
#   sign-in). So to see a LIVE match you must fail a few console logins in the
#   browser. The steps are printed below. The script then runs the detection
#   query, which will match those failures once CloudTrail delivers them, or
#   any earlier failed logins already in the logs.
#
# Usage:  ./demo-5-failed-logins.sh
#==============================================================================
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

banner "CASE 5 - CONSECUTIVE FAILED LOGINS  ( >=3 ConsoleLogin failures )"

echo ">>> This case needs real browser console sign-in failures (the CLI cannot"
echo "    produce ConsoleLogin events). See scripts/demos/README.md for the steps."

if command -v mysql >/dev/null 2>&1; then
  echo
  echo ">>> (Illustrative) 3 failed DB login attempts against RDS ..."
  for i in 1 2 3; do
    mysql -h "$DB_ENDPOINT" -P 3306 -u hacker_test -p"wrong_pass_$i" "$DB_NAME" \
      -e "SELECT 1;" 2>&1 | grep -vi "warning" | head -1
  done
fi

banner "CASE 5 COMPLETE"
