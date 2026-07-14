#!/usr/bin/env bash
#==============================================================================
# CASE 6 - BULK S3 DOWNLOAD  (mass data exfiltration)
#
#   Rule    : one IP downloads a large number of objects from S3.
#   Trigger : > 100 GetObject events from the same sourceIPAddress.
#   Real-world meaning: someone pulling an entire bucket - the exfiltration
#   step of a data leak.
#
# NOTE - S3 DATA EVENTS
#   GetObject is an S3 *data* event, which CloudTrail does not log by default.
#   That logging is turned on by the DEFENDER in scripts/setup-automation.sh
#   (an attacker would never log their own downloads), so this attacker script
#   just performs the downloads. If you skipped setup-automation.sh, enable it
#   once with:
#     aws cloudtrail put-event-selectors --region <REGION> --trail-name <TRAIL> \
#       --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true,
#       "DataResources":[{"Type":"AWS::S3::Object","Values":["arn:aws:s3:::<BUCKET>/"]}]}]'
#
# Usage:  ./demo-6-bulk-download.sh
#==============================================================================
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

banner "CASE 6 - BULK S3 DOWNLOAD  ( >100 GetObject calls from one IP )"

# Seed a few objects to read.
echo
echo ">>> Uploading 5 sample objects to download ..."
TMP="$PROJECT_ROOT/.pbl-tmp"; mkdir -p "$TMP"
for n in 1 2 3 4 5; do
  echo "secret-record-$n confidential payload" > "$TMP/leak_$n.txt"
  aws s3 cp "$TMP/leak_$n.txt" "s3://${S3_BUCKET}/demo-data/leak_$n.txt" --region "$REGION" >/dev/null 2>&1
done
rm -f "$TMP"/leak_*.txt

echo ">>> Downloading objects 120 times (simulating bulk exfiltration) ..."
for i in $(seq 1 120); do
  obj=$(( (i % 5) + 1 ))
  aws s3api get-object --bucket "$S3_BUCKET" --key "demo-data/leak_${obj}.txt" \
    "$TMP/dl.txt" --region "$REGION" >/dev/null 2>&1
  printf '\r    downloaded %d/120 objects' "$i"
done
echo
rm -f "$TMP/dl.txt"
info "120 GetObject calls issued from this IP."

banner "CASE 6 COMPLETE"
