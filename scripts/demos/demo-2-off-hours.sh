#!/usr/bin/env bash
#==============================================================================
# CASE 2 - OFF-HOURS ACCESS
#
#   Rule    : account activity during hours when no legitimate user should be
#             working - between 00:00 and 05:00 UTC.
#   Trigger : any event whose eventTime falls in the 00:00-05:00 UTC window.
#   Real-world meaning: legitimate staff are asleep; data access at 3 AM is a
#   classic exfiltration signature.
#
# HOW THIS DEMO TRIGGERS IT
#   We generate some activity now. Whether it *counts* as off-hours depends on
#   the current UTC time - the rule keys off the recorded eventTime, not on
#   when you run the query. The script tells you the current UTC hour so you
#   know whether fresh activity will match. (Older log entries created during
#   00:00-05:00 UTC will match regardless of when you run this.)
#
# Usage:  ./demo-2-off-hours.sh
#==============================================================================
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

banner "CASE 2 - OFF-HOURS ACCESS  ( activity 00:00-05:00 UTC )"

UTC_HOUR=$(date -u +%H)
echo "    Current UTC time : $(date -u '+%Y-%m-%d %H:%M:%S') UTC"
echo "    Current UTC hour : $UTC_HOUR"
if [ "$((10#$UTC_HOUR))" -ge 0 ] && [ "$((10#$UTC_HOUR))" -le 5 ]; then
  echo ">>> You are INSIDE the off-hours window - activity generated now WILL match."
else
  warn "You are OUTSIDE 00:00-05:00 UTC, so activity generated right now will NOT"
  warn "match this rule. The query still reports any PAST events that landed in"
  warn "the off-hours window. To force a live match, run this demo between"
  warn "00:00 and 05:00 UTC."
fi

echo
echo ">>> Generating a few API events (timestamped 'now' by CloudTrail) ..."
for i in 1 2 3 4 5; do
  aws sts get-caller-identity --region "$REGION" >/dev/null 2>&1
done
info "Done."

lag_note

run_athena "Off-hours activity (00:00-05:00 UTC)" \
"SELECT eventTime, eventSource, eventName, sourceIPAddress
 FROM cloudtrail_logs
 WHERE hour(from_iso8601_timestamp(eventTime)) BETWEEN 0 AND 5
 ORDER BY eventTime DESC
 LIMIT 25;"

invoke_detector_if_present

banner "CASE 2 COMPLETE"
