#!/usr/bin/env bash
#==============================================================================
# CASE 6 - BULK S3 DOWNLOAD  (mass data exfiltration)
#
#   Rule    : one IP downloads a large number of objects from S3.
#   Trigger : > 100 GetObject events from the same sourceIPAddress.
#   Real-world meaning: someone pulling an entire bucket - the exfiltration
#   step of a data leak.
#
# IMPORTANT - S3 DATA EVENTS MUST BE ON
#   GetObject is an S3 *data* event. By default CloudTrail records only
#   *management* events, so object reads are invisible. This demo first turns
#   ON S3 data-event logging for the bucket (a small extra CloudTrail cost),
#   then downloads objects 120 times to cross the >100 threshold.
#   teardown.sh deletes the whole trail, so the data-event selector goes with
#   it. To re-run with only management events, comment out enable_data_events.
#
# Usage:  ./demo-6-bulk-download.sh
#==============================================================================
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

banner "CASE 6 - BULK S3 DOWNLOAD  ( >100 GetObject calls from one IP )"

enable_data_events() {
  echo ">>> Enabling S3 data-event logging on trail $TRAIL_NAME for this bucket ..."
  aws cloudtrail put-event-selectors --region "$REGION" \
    --trail-name "$TRAIL_NAME" \
    --event-selectors "[{
      \"ReadWriteType\": \"All\",
      \"IncludeManagementEvents\": true,
      \"DataResources\": [{
        \"Type\": \"AWS::S3::Object\",
        \"Values\": [\"arn:aws:s3:::${S3_BUCKET}/\"]
      }]
    }]" >/dev/null \
    && info "Data events ON (GetObject on $S3_BUCKET is now logged)." \
    || warn "Could not enable data events (need cloudtrail:PutEventSelectors)."
}

enable_data_events

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

lag_note

run_athena "Bulk downloads (>100 GetObject from one IP)" \
"SELECT sourceIPAddress, COUNT(*) AS downloads
 FROM cloudtrail_logs
 WHERE eventName = 'GetObject'
 GROUP BY sourceIPAddress
 HAVING COUNT(*) > 100
 ORDER BY downloads DESC;"

invoke_detector_if_present

banner "CASE 6 COMPLETE"
