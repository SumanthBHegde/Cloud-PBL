#!/usr/bin/env bash
#==============================================================================
# CASE 4 - POLICY / PERMISSION MODIFICATION
#
#   Rule    : someone changes the security posture of the log/data bucket.
#   Trigger : eventName is PutBucketPolicy or PutBucketAcl.
#   Real-world meaning: an attacker weakening bucket permissions (e.g. to make
#   data public or to grant themselves access) before exfiltration - or
#   tampering with the very bucket that stores the audit logs.
#
# HOW THIS DEMO TRIGGERS IT
#   We re-apply the bucket's OWN existing policy (a no-op change) so a real
#   PutBucketPolicy management event is recorded by CloudTrail. Nothing about
#   the bucket's actual permissions changes.
#
# Usage:  ./demo-4-policy-modification.sh
#==============================================================================
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

banner "CASE 4 - POLICY MODIFICATION  ( PutBucketPolicy / PutBucketAcl )"

TMP="$PROJECT_ROOT/.pbl-tmp"
mkdir -p "$TMP"
POLICY_FILE="$TMP/case4-bucket-policy.json"
trap 'rm -f "$POLICY_FILE"' EXIT

echo ">>> Reading the current bucket policy for $S3_BUCKET ..."
if aws s3api get-bucket-policy --bucket "$S3_BUCKET" --query Policy --output text > "$POLICY_FILE" 2>/dev/null; then
  echo ">>> Re-applying the SAME policy (no-op) to emit a PutBucketPolicy event ..."
  aws s3api put-bucket-policy --bucket "$S3_BUCKET" --policy "file://$POLICY_FILE" \
    && info "PutBucketPolicy event generated (bucket permissions unchanged)."
else
  warn "Could not read existing bucket policy; emitting a PutBucketAcl event instead."
  aws s3api put-bucket-acl --bucket "$S3_BUCKET" --acl private \
    && info "PutBucketAcl event generated (bucket ACL unchanged)."
fi

lag_note

run_athena "Bucket policy / ACL tampering (PutBucketPolicy, PutBucketAcl)" \
"SELECT eventTime, eventName, sourceIPAddress, awsRegion, userIdentity.userName AS who
 FROM cloudtrail_logs
 WHERE eventName IN ('PutBucketPolicy', 'PutBucketAcl')
 ORDER BY eventTime DESC
 LIMIT 25;"

invoke_detector_if_present

banner "CASE 4 COMPLETE"
