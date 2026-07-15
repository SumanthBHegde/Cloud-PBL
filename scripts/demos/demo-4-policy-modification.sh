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

TMP="$PROJECT_ROOT/.pbl-tmp"
mkdir -p "$TMP"
POLICY_FILE="$TMP/case4-bucket-policy.json"
trap 'rm -f "$POLICY_FILE"' EXIT

if aws s3api get-bucket-policy --bucket "$S3_BUCKET" --query Policy --output text > "$POLICY_FILE" 2>/dev/null; then
  aws s3api put-bucket-policy --bucket "$S3_BUCKET" --policy "file://$POLICY_FILE" >/dev/null 2>&1
else
  aws s3api put-bucket-acl --bucket "$S3_BUCKET" --acl private >/dev/null 2>&1
fi
