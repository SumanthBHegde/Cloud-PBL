#!/usr/bin/env bash
#==============================================================================
# CASE 3 - UNKNOWN / UNAUTHORIZED REGION
#
#   Rule    : API calls originating from an AWS region the project does not
#             use. The whole stack lives in ap-south-1 (Mumbai); anything from
#             another region is suspicious.
#   Trigger : any event whose awsRegion is NOT ap-south-1.
#   Real-world meaning: attackers often operate from a different region to spin
#   up resources or read data where defenders aren't looking.
#
# HOW THIS DEMO TRIGGERS IT
#   We make a read-only API call in a DIFFERENT region (us-east-1). Because the
#   CloudTrail trail is multi-region, that event is captured with
#   awsRegion = 'us-east-1', which the rule flags as unknown.
#
# Usage:  ./demo-3-unknown-region.sh
#==============================================================================
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

banner "CASE 3 - UNKNOWN REGION  ( API call from outside ap-south-1 )"

FOREIGN_REGION="us-east-1"
echo ">>> Making read-only API calls in a foreign region: $FOREIGN_REGION ..."
for i in 1 2 3; do
  aws ec2 describe-availability-zones --region "$FOREIGN_REGION" >/dev/null 2>&1
  aws sts get-caller-identity --region "$FOREIGN_REGION" >/dev/null 2>&1
done
info "Done. CloudTrail (multi-region trail) will record awsRegion=$FOREIGN_REGION."

lag_note

run_athena "API activity from unauthorized regions (!= ap-south-1)" \
"SELECT awsRegion, COUNT(*) AS cnt
 FROM cloudtrail_logs
 WHERE awsRegion NOT IN ('ap-south-1')
 GROUP BY awsRegion
 ORDER BY cnt DESC;"

invoke_detector_if_present

banner "CASE 3 COMPLETE"
