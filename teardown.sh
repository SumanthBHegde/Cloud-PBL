#!/usr/bin/env bash
#==============================================================================
# Cloud PBL - Data Leak Monitoring System - FULL TEARDOWN SCRIPT
#
# Deletes EVERY resource setup.sh created so you stop incurring AWS cost.
# Reads ./pbl-state.env produced by setup.sh.
#
# Order matters (reverse of creation, plus dependency unwinding):
#   1.  Lambda function + IAM role
#   2.  SNS topic (auto-deletes its subscriptions)
#   3.  Athena cloudtrail_logs table (drop)
#   4.  CloudTrail (stop + delete)
#   5.  RDS instance (skip final snapshot) + DB subnet group
#   6.  S3 bucket (empty + delete, incl. all versions)
#   7.  Security group
#   8.  Route table associations + route table
#   9.  Subnets
#  10.  Internet gateway (detach + delete)
#  11.  VPC
#
# Usage:
#   chmod +x teardown.sh
#   ./teardown.sh
#==============================================================================
set -uo pipefail   # NOT -e: we want best-effort cleanup; keep going on errors

STATE_FILE="./pbl-state.env"
if [ ! -f "$STATE_FILE" ]; then
  echo "ERROR: $STATE_FILE not found. Run setup.sh first (or recreate it manually)."
  exit 1
fi
# shellcheck disable=SC1090
source "$STATE_FILE"

echo "=============================================="
echo " Cloud PBL TEARDOWN starting in $REGION"
echo " (best-effort: continues on individual errors)"
echo "=============================================="

step() { echo; echo ">>> $*"; }

#------------------------------------------------------------------------------
# 0. Automation layer (setup-automation.sh) - EventBridge rule + detector Lambda
#    Removed first so nothing keeps invoking while the rest is torn down.
#------------------------------------------------------------------------------
step "[0] Removing automation layer (EventBridge + detector Lambda) ..."
if [ -n "${SCHEDULE_RULE_NAME:-}" ]; then
  aws events remove-targets --region "$REGION" --rule "$SCHEDULE_RULE_NAME" --ids detector || true
  aws events delete-rule --region "$REGION" --name "$SCHEDULE_RULE_NAME" || true
fi
if [ -n "${DETECTOR_NAME:-}" ]; then
  aws lambda delete-function --region "$REGION" --function-name "$DETECTOR_NAME" || true
fi
if [ -n "${DETECTOR_ROLE_NAME:-}" ]; then
  aws iam detach-role-policy --role-name "$DETECTOR_ROLE_NAME" \
    --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole || true
  for IP in $(aws iam list-role-policies --role-name "$DETECTOR_ROLE_NAME" --query 'PolicyNames[]' --output text 2>/dev/null); do
    aws iam delete-role-policy --role-name "$DETECTOR_ROLE_NAME" --policy-name "$IP" || true
  done
  aws iam delete-role --role-name "$DETECTOR_ROLE_NAME" || true
fi

#------------------------------------------------------------------------------
# 1. Lambda + IAM role
#------------------------------------------------------------------------------
step "[1] Deleting Lambda function ..."
if [ -n "${LAMBDA_NAME:-}" ]; then
  aws lambda delete-function --region "$REGION" --function-name "$LAMBDA_NAME" || true
fi

step "[1] Detaching policies + deleting IAM role ..."
if [ -n "${ROLE_NAME:-}" ]; then
  for P in arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole \
           arn:aws:iam::aws:policy/AmazonSNSFullAccess ; do
    aws iam detach-role-policy --role-name "$ROLE_NAME" --policy-arn "$P" || true
  done
  # remove any inline policies just in case
  for IP in $(aws iam list-role-policies --role-name "$ROLE_NAME" --query 'PolicyNames[]' --output text 2>/dev/null); do
    aws iam delete-role-policy --role-name "$ROLE_NAME" --policy-name "$IP" || true
  done
  aws iam delete-role --role-name "$ROLE_NAME" || true
fi

#------------------------------------------------------------------------------
# 2. SNS topic (subscriptions die with the topic)
#------------------------------------------------------------------------------
step "[2] Deleting SNS topic ..."
if [ -n "${SNS_TOPIC_ARN:-}" ]; then
  aws sns delete-topic --region "$REGION" --topic-arn "$SNS_TOPIC_ARN" || true
fi

#------------------------------------------------------------------------------
# 3. Athena external table
#------------------------------------------------------------------------------
step "[3] Dropping Athena cloudtrail_logs table ..."
if [ -n "${S3_BUCKET:-}" ]; then
  aws athena start-query-execution --region "$REGION" \
    --query-string "DROP TABLE IF EXISTS cloudtrail_logs;" \
    --query-execution-context "Database=default" \
    --result-configuration "OutputLocation=s3://${S3_BUCKET}/athena-results/" \
    --work-group primary >/dev/null 2>&1 || true
fi

#------------------------------------------------------------------------------
# 4. CloudTrail
#------------------------------------------------------------------------------
step "[4] Stopping + deleting CloudTrail ..."
if [ -n "${TRAIL_NAME:-}" ]; then
  aws cloudtrail stop-logging --region "$REGION" --name "$TRAIL_NAME" || true
  aws cloudtrail delete-trail --region "$REGION" --name "$TRAIL_NAME" || true
fi

#------------------------------------------------------------------------------
# 5. RDS instance + subnet group
#------------------------------------------------------------------------------
step "[5] Deleting RDS instance (skipping final snapshot) ..."
if [ -n "${DB_IDENTIFIER:-}" ]; then
  aws rds delete-db-instance --region "$REGION" \
    --db-instance-identifier "$DB_IDENTIFIER" \
    --skip-final-snapshot \
    --delete-automated-backups || true

  echo "    Waiting for DB to be fully deleted (this takes a few minutes) ..."
  aws rds wait db-instance-deleted --region "$REGION" --db-instance-identifier "$DB_IDENTIFIER" || true
fi

step "[5] Deleting DB subnet group ..."
if [ -n "${DB_SUBNET_GROUP:-}" ]; then
  aws rds delete-db-subnet-group --region "$REGION" --db-subnet-group-name "$DB_SUBNET_GROUP" || true
fi

#------------------------------------------------------------------------------
# 6. S3 bucket - empty (incl. versions) then delete
#------------------------------------------------------------------------------
step "[6] Emptying + deleting S3 bucket ..."
if [ -n "${S3_BUCKET:-}" ]; then
  # Remove current objects
  aws s3 rm "s3://${S3_BUCKET}" --recursive || true
  # Remove all versions and delete markers if versioning ever got enabled
  python3 - "$S3_BUCKET" "$REGION" <<'PY' || true
import sys, boto3
bucket, region = sys.argv[1], sys.argv[2]
s3 = boto3.client('s3', region_name=region)
paginator = s3.get_paginator('list_object_versions')
to_delete = []
for page in paginator.paginate(Bucket=bucket):
    for v in page.get('Versions', []) + page.get('DeleteMarkers', []):
        to_delete.append({'Key': v['Key'], 'VersionId': v['VersionId']})
        if len(to_delete) == 1000:
            s3.delete_objects(Bucket=bucket, Delete={'Objects': to_delete})
            to_delete = []
if to_delete:
    s3.delete_objects(Bucket=bucket, Delete={'Objects': to_delete})
PY
  aws s3api delete-bucket --bucket "$S3_BUCKET" --region "$REGION" || true
fi

#------------------------------------------------------------------------------
# 7. Security group  (must come after RDS is gone)
#------------------------------------------------------------------------------
step "[7] Deleting Security Group ..."
if [ -n "${SG_ID:-}" ]; then
  aws ec2 delete-security-group --region "$REGION" --group-id "$SG_ID" || true
fi

#------------------------------------------------------------------------------
# 8. Route table associations + route table
#------------------------------------------------------------------------------
step "[8] Removing route table associations + route table ..."
if [ -n "${RT_ASSOC1:-}" ]; then
  aws ec2 disassociate-route-table --region "$REGION" --association-id "$RT_ASSOC1" || true
fi
if [ -n "${RT_ASSOC2:-}" ]; then
  aws ec2 disassociate-route-table --region "$REGION" --association-id "$RT_ASSOC2" || true
fi
if [ -n "${RT_ID:-}" ]; then
  aws ec2 delete-route-table --region "$REGION" --route-table-id "$RT_ID" || true
fi

#------------------------------------------------------------------------------
# 9. Subnets
#------------------------------------------------------------------------------
step "[9] Deleting subnets ..."
if [ -n "${SUB1_ID:-}" ]; then aws ec2 delete-subnet --region "$REGION" --subnet-id "$SUB1_ID" || true; fi
if [ -n "${SUB2_ID:-}" ]; then aws ec2 delete-subnet --region "$REGION" --subnet-id "$SUB2_ID" || true; fi

#------------------------------------------------------------------------------
# 10. Internet Gateway
#------------------------------------------------------------------------------
step "[10] Detaching + deleting IGW ..."
if [ -n "${IGW_ID:-}" ] && [ -n "${VPC_ID:-}" ]; then
  aws ec2 detach-internet-gateway --region "$REGION" --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID" || true
  aws ec2 delete-internet-gateway --region "$REGION" --internet-gateway-id "$IGW_ID" || true
fi

#------------------------------------------------------------------------------
# 11. VPC
#------------------------------------------------------------------------------
step "[11] Deleting VPC ..."
if [ -n "${VPC_ID:-}" ]; then
  aws ec2 delete-vpc --region "$REGION" --vpc-id "$VPC_ID" || true
fi

#------------------------------------------------------------------------------
# Done
#------------------------------------------------------------------------------
echo
echo "=============================================="
echo " TEARDOWN COMPLETE"
echo "=============================================="
echo " Verify in the AWS console that nothing is left:"
echo "   - Lambda functions     (region $REGION)"
echo "   - IAM roles            (search '${ROLE_NAME:-<lambda role>}')"
echo "   - SNS topics           (region $REGION)"
echo "   - CloudTrail trails    (region $REGION)"
echo "   - RDS instances        (region $REGION)"
echo "   - S3 buckets           (global - search '${S3_BUCKET:-<bucket>}')"
echo "   - VPC + subnets + IGW  (region $REGION)"
echo
echo " You can now safely remove $STATE_FILE"
