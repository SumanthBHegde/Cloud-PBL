#!/usr/bin/env bash
#==============================================================================
# Cloud PBL - Data Leak Monitoring System - FULL SETUP SCRIPT
#
# Recreates the entire project using AWS CLI:
#   VPC + IGW + Subnets + Route Table
#   S3 bucket (CloudTrail log destination + athena-results folder)
#   CloudTrail multi-region trail
#   RDS MySQL instance + sample employee_data table
#   Athena workgroup query result location + cloudtrail_logs external table
#   SNS topic + email subscription
#   Lambda function (data-leak-alert-handler) with SNS publish permission
#
# Prerequisites:
#   - AWS CLI v2 installed and configured (`aws configure`)
#   - jq installed
#   - mysql client installed (for seeding the DB)
#   - zip installed
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh
#
# After it finishes, all created resource IDs are saved to ./pbl-state.env
# which the teardown.sh script reads to cleanly remove everything.
#==============================================================================
set -euo pipefail

#------------------------------------------------------------------------------
# CONFIG - tweak these if you want
#------------------------------------------------------------------------------
SUFFIX="${SUFFIX:-1rv25mc103}"          # unique tag from the PPT
REGION="${REGION:-ap-south-1}"           # Mumbai
AZ_A="${AZ_A:-ap-south-1a}"
AZ_B="${AZ_B:-ap-south-1b}"

VPC_NAME="PBL_VPC_DONT_DELETE"
VPC_CIDR="10.0.0.0/16"
SUB1_CIDR="10.0.1.0/24"
SUB2_CIDR="10.0.2.0/24"

IGW_NAME="PBL_IGW_${SUFFIX}"
RT_NAME="PBL_RT_${SUFFIX}"

S3_BUCKET="data-leak-monitoring-logs-sumanth-${SUFFIX}"

TRAIL_NAME="DataLeakTrail_${SUFFIX}"

DB_IDENTIFIER="pbldatabase"
DB_NAME="PBL_DB_${SUFFIX}"
DB_USER="admin"
DB_PASS="${DB_PASS:-Admin12345!}"        # change me or export DB_PASS
DB_CLASS="db.t4g.micro"
DB_STORAGE=20
DB_ENGINE_VERSION="8.4.8"
SG_NAME="PBL_VPC_SG_RDS"

SNS_TOPIC_NAME="data-leak-alerts-sumanth-${SUFFIX}"
SNS_EMAIL="${SNS_EMAIL:-sumanthhegde002@gmail.com}"   # override with env var

LAMBDA_NAME="data-leak-alert-handler-sumanth-${SUFFIX}"
LAMBDA_RUNTIME="python3.12"

# Work dir for temp files (policy JSON, etc). Must be a RELATIVE path inside
# the project: the AWS CLI on Windows is a native binary that cannot read
# Git-Bash paths like /tmp/... , so we hand it a relative file:// path that
# both the shell and the Windows CLI resolve to the same place.
TMPDIR_LOCAL="./.pbl-tmp"
mkdir -p "$TMPDIR_LOCAL"
trap 'rm -rf "$TMPDIR_LOCAL"' EXIT

STATE_FILE="./pbl-state.env"
: > "$STATE_FILE"

save() { echo "$1=\"$2\"" >> "$STATE_FILE"; }

echo "=============================================="
echo " Cloud PBL setup starting in region: $REGION"
echo " Suffix: $SUFFIX"
echo "=============================================="

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
save ACCOUNT_ID "$ACCOUNT_ID"
save REGION "$REGION"
save SUFFIX "$SUFFIX"
echo "Account: $ACCOUNT_ID"

#------------------------------------------------------------------------------
# PART A : VPC + IGW + Subnets + Route Table
#------------------------------------------------------------------------------
echo
echo ">>> [A] Creating VPC ..."
VPC_ID=$(aws ec2 create-vpc \
  --region "$REGION" \
  --cidr-block "$VPC_CIDR" \
  --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=$VPC_NAME}]" \
  --query 'Vpc.VpcId' --output text)
save VPC_ID "$VPC_ID"
echo "    VPC_ID=$VPC_ID"

aws ec2 modify-vpc-attribute --region "$REGION" --vpc-id "$VPC_ID" --enable-dns-support  "{\"Value\":true}"
aws ec2 modify-vpc-attribute --region "$REGION" --vpc-id "$VPC_ID" --enable-dns-hostnames "{\"Value\":true}"

echo ">>> [A] Creating Internet Gateway ..."
IGW_ID=$(aws ec2 create-internet-gateway --region "$REGION" \
  --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=$IGW_NAME}]" \
  --query 'InternetGateway.InternetGatewayId' --output text)
save IGW_ID "$IGW_ID"
aws ec2 attach-internet-gateway --region "$REGION" --vpc-id "$VPC_ID" --internet-gateway-id "$IGW_ID"
echo "    IGW_ID=$IGW_ID"

echo ">>> [A] Creating subnets ..."
SUB1_ID=$(aws ec2 create-subnet --region "$REGION" --vpc-id "$VPC_ID" \
  --cidr-block "$SUB1_CIDR" --availability-zone "$AZ_A" \
  --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=sub1-pub}]" \
  --query 'Subnet.SubnetId' --output text)
SUB2_ID=$(aws ec2 create-subnet --region "$REGION" --vpc-id "$VPC_ID" \
  --cidr-block "$SUB2_CIDR" --availability-zone "$AZ_B" \
  --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=sub2-priv}]" \
  --query 'Subnet.SubnetId' --output text)
save SUB1_ID "$SUB1_ID"
save SUB2_ID "$SUB2_ID"
echo "    sub1-pub=$SUB1_ID  sub2-priv=$SUB2_ID"

aws ec2 modify-subnet-attribute --region "$REGION" --subnet-id "$SUB1_ID" --map-public-ip-on-launch
aws ec2 modify-subnet-attribute --region "$REGION" --subnet-id "$SUB2_ID" --map-public-ip-on-launch

echo ">>> [A] Creating Route Table + 0.0.0.0/0 -> IGW + subnet assoc ..."
RT_ID=$(aws ec2 create-route-table --region "$REGION" --vpc-id "$VPC_ID" \
  --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=$RT_NAME}]" \
  --query 'RouteTable.RouteTableId' --output text)
save RT_ID "$RT_ID"
aws ec2 create-route --region "$REGION" --route-table-id "$RT_ID" \
  --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW_ID" >/dev/null
RT_ASSOC1=$(aws ec2 associate-route-table --region "$REGION" --route-table-id "$RT_ID" --subnet-id "$SUB1_ID" --query 'AssociationId' --output text)
RT_ASSOC2=$(aws ec2 associate-route-table --region "$REGION" --route-table-id "$RT_ID" --subnet-id "$SUB2_ID" --query 'AssociationId' --output text)
save RT_ASSOC1 "$RT_ASSOC1"
save RT_ASSOC2 "$RT_ASSOC2"
echo "    RT_ID=$RT_ID"

#------------------------------------------------------------------------------
# PART B : S3 bucket for logs
#------------------------------------------------------------------------------
echo
echo ">>> [B] Creating S3 bucket: $S3_BUCKET ..."
if [ "$REGION" = "us-east-1" ]; then
  aws s3api create-bucket --bucket "$S3_BUCKET" --region "$REGION"
else
  aws s3api create-bucket --bucket "$S3_BUCKET" --region "$REGION" \
    --create-bucket-configuration "LocationConstraint=$REGION"
fi
save S3_BUCKET "$S3_BUCKET"

# Block all public access
aws s3api put-public-access-block --bucket "$S3_BUCKET" \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Default SSE-S3 encryption + bucket key
aws s3api put-bucket-encryption --bucket "$S3_BUCKET" \
  --server-side-encryption-configuration '{
    "Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BucketKeyEnabled":true}]
  }'

# Bucket policy that lets CloudTrail write into it
cat > "$TMPDIR_LOCAL/ct-bucket-policy.json" <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {"Service":"cloudtrail.amazonaws.com"},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::${S3_BUCKET}"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {"Service":"cloudtrail.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::${S3_BUCKET}/AWSLogs/${ACCOUNT_ID}/*",
      "Condition": {"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}
    }
  ]
}
EOF
aws s3api put-bucket-policy --bucket "$S3_BUCKET" --policy "file://$TMPDIR_LOCAL/ct-bucket-policy.json"

# athena-results folder
aws s3api put-object --bucket "$S3_BUCKET" --key "athena-results/" >/dev/null
echo "    Bucket ready (with athena-results/ prefix)"

#------------------------------------------------------------------------------
# PART C : CloudTrail
#------------------------------------------------------------------------------
echo
echo ">>> [C] Creating CloudTrail: $TRAIL_NAME ..."
aws cloudtrail create-trail \
  --region "$REGION" \
  --name "$TRAIL_NAME" \
  --s3-bucket-name "$S3_BUCKET" \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --include-global-service-events >/dev/null || \
aws cloudtrail update-trail \
  --region "$REGION" \
  --name "$TRAIL_NAME" \
  --s3-bucket-name "$S3_BUCKET" \
  --is-multi-region-trail \
  --enable-log-file-validation >/dev/null
save TRAIL_NAME "$TRAIL_NAME"

aws cloudtrail start-logging --region "$REGION" --name "$TRAIL_NAME"
echo "    Trail logging started"

#------------------------------------------------------------------------------
# PART D : RDS MySQL
#------------------------------------------------------------------------------
echo
echo ">>> [D] Creating DB subnet group + security group ..."
DB_SUBNET_GROUP="pbl-db-subnet-${SUFFIX}"
aws rds create-db-subnet-group --region "$REGION" \
  --db-subnet-group-name "$DB_SUBNET_GROUP" \
  --db-subnet-group-description "PBL DB subnet group" \
  --subnet-ids "$SUB1_ID" "$SUB2_ID" >/dev/null
save DB_SUBNET_GROUP "$DB_SUBNET_GROUP"

SG_ID=$(aws ec2 create-security-group --region "$REGION" \
  --vpc-id "$VPC_ID" \
  --group-name "$SG_NAME" \
  --description "PBL RDS SG" \
  --query 'GroupId' --output text)
save SG_ID "$SG_ID"

aws ec2 authorize-security-group-ingress --region "$REGION" \
  --group-id "$SG_ID" \
  --protocol tcp --port 3306 --cidr 0.0.0.0/0 >/dev/null
echo "    SG_ID=$SG_ID (3306 open to 0.0.0.0/0)"

echo ">>> [D] Creating RDS MySQL instance (this takes ~6-10 minutes) ..."
aws rds create-db-instance --region "$REGION" \
  --db-instance-identifier "$DB_IDENTIFIER" \
  --db-name "$DB_NAME" \
  --engine mysql \
  --engine-version "$DB_ENGINE_VERSION" \
  --db-instance-class "$DB_CLASS" \
  --allocated-storage "$DB_STORAGE" \
  --storage-type gp2 \
  --master-username "$DB_USER" \
  --master-user-password "$DB_PASS" \
  --vpc-security-group-ids "$SG_ID" \
  --db-subnet-group-name "$DB_SUBNET_GROUP" \
  --publicly-accessible \
  --backup-retention-period 1 \
  --no-multi-az \
  --auto-minor-version-upgrade \
  --no-deletion-protection \
  --copy-tags-to-snapshot \
  --storage-encrypted >/dev/null
save DB_IDENTIFIER "$DB_IDENTIFIER"

echo "    Waiting for DB to become available ..."
aws rds wait db-instance-available --region "$REGION" --db-instance-identifier "$DB_IDENTIFIER"

DB_ENDPOINT=$(aws rds describe-db-instances --region "$REGION" \
  --db-instance-identifier "$DB_IDENTIFIER" \
  --query 'DBInstances[0].Endpoint.Address' --output text)
save DB_ENDPOINT "$DB_ENDPOINT"
echo "    DB_ENDPOINT=$DB_ENDPOINT"

# Seed table + sample rows so SELECT * FROM employee_data works (Part E).
# The RDS endpoint DNS can take a minute to resolve after the instance reports
# "available", so we retry. A seed failure must NOT abort the rest of setup
# (everything after this is independent) — hence the explicit guard.
SEED_SQL='CREATE TABLE IF NOT EXISTS employee_data (
  emp_id     INT PRIMARY KEY,
  name       VARCHAR(100),
  salary     INT,
  email      VARCHAR(200),
  department VARCHAR(100)
);
INSERT IGNORE INTO employee_data VALUES
 (101,"Rahul Sharma",  85000,"rahul.sharma@company.com","Engineering"),
 (102,"Priya Patel",   92000,"priya.patel@company.com","Finance"),
 (103,"Amit Mishra",   64000,"amit.mishra@company.com","Human Resources"),
 (104,"Sneha Rao",    120000,"sneha.rao@company.com","Executive Management"),
 (105,"Vikram Singh",  78000,"vikram.singh@company.com","Marketing"),
 (106,"Neha Gupta",    88000,"neha.gupta@company.com","Engineering"),
 (107,"Arjun Verma",   95000,"arjun.verma@company.com","Finance");'

if command -v mysql >/dev/null 2>&1; then
  echo ">>> [D] Seeding employee_data table (waiting for endpoint DNS + connectivity) ..."
  SEEDED=0
  for attempt in $(seq 1 12); do
    if echo "$SEED_SQL" | mysql -h "$DB_ENDPOINT" -P 3306 -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" 2>/tmp/mysql_seed_err; then
      SEEDED=1
      break
    fi
    echo "    attempt $attempt/12 failed ($(tr -d '\n' </tmp/mysql_seed_err | tail -c 120)); retrying in 15s ..."
    sleep 15
  done
  if [ "$SEEDED" = "1" ]; then
    echo "    employee_data seeded"
  else
    echo "    [WARN] could not seed after retries. Seed manually once DNS resolves:"
    echo "    mysql -h $DB_ENDPOINT -P 3306 -u $DB_USER -p$DB_PASS $DB_NAME"
  fi
else
  echo "    [skip] mysql client not installed - seed the table manually:"
  echo "    mysql -h $DB_ENDPOINT -P 3306 -u $DB_USER -p"
fi

#------------------------------------------------------------------------------
# PART F : Athena - workgroup output location + external table
#------------------------------------------------------------------------------
echo
echo ">>> [F] Configuring Athena primary workgroup result location ..."
aws athena update-work-group --region "$REGION" --work-group primary \
  --configuration-updates "ResultConfigurationUpdates={OutputLocation=s3://${S3_BUCKET}/athena-results/}" >/dev/null

echo ">>> [F] Creating Athena external table cloudtrail_logs ..."
# CloudTrail writes gzipped JSON wrapped in a {\"Records\":[...]} envelope, so the
# generic JsonSerDe leaves every column NULL. The CloudTrail-specific SerDe below
# flattens the Records[] array correctly. LOCATION must point at the CloudTrail/
# prefix under the account ID, not the bucket root.
ATHENA_QUERY="CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail_logs (
  eventVersion STRING,
  eventTime STRING,
  eventSource STRING,
  eventName STRING,
  sourceIPAddress STRING,
  awsRegion STRING,
  userIdentity STRUCT<type:STRING, userName:STRING>,
  errorCode STRING,
  errorMessage STRING
)
ROW FORMAT SERDE 'com.amazon.emr.hive.serde.CloudTrailSerde'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://${S3_BUCKET}/AWSLogs/${ACCOUNT_ID}/CloudTrail/';"

QID=$(aws athena start-query-execution --region "$REGION" \
  --query-string "$ATHENA_QUERY" \
  --query-execution-context "Database=default" \
  --result-configuration "OutputLocation=s3://${S3_BUCKET}/athena-results/" \
  --work-group primary \
  --query 'QueryExecutionId' --output text)
echo "    Athena query id: $QID"

#------------------------------------------------------------------------------
# PART G : SNS topic + email subscription
#------------------------------------------------------------------------------
echo
echo ">>> [G] Creating SNS topic + email subscription ..."
SNS_TOPIC_ARN=$(aws sns create-topic --region "$REGION" \
  --name "$SNS_TOPIC_NAME" \
  --attributes DisplayName=ALERT \
  --query 'TopicArn' --output text)
save SNS_TOPIC_ARN "$SNS_TOPIC_ARN"
echo "    SNS_TOPIC_ARN=$SNS_TOPIC_ARN"

aws sns subscribe --region "$REGION" \
  --topic-arn "$SNS_TOPIC_ARN" \
  --protocol email \
  --notification-endpoint "$SNS_EMAIL" >/dev/null
echo "    Subscribed $SNS_EMAIL  --  CHECK YOUR INBOX AND CONFIRM"

#------------------------------------------------------------------------------
# PART H : Lambda function
#------------------------------------------------------------------------------
echo
echo ">>> [H] Creating IAM role for Lambda ..."
ROLE_NAME="${LAMBDA_NAME}-role"
TRUST='{
  "Version":"2012-10-17",
  "Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]
}'
ROLE_ARN=$(aws iam create-role --role-name "$ROLE_NAME" \
  --assume-role-policy-document "$TRUST" \
  --query 'Role.Arn' --output text)
save ROLE_NAME "$ROLE_NAME"
save ROLE_ARN  "$ROLE_ARN"

aws iam attach-role-policy --role-name "$ROLE_NAME" \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam attach-role-policy --role-name "$ROLE_NAME" \
  --policy-arn arn:aws:iam::aws:policy/AmazonSNSFullAccess

# IAM eventual consistency
echo "    Waiting 15s for IAM propagation ..."
sleep 15

echo ">>> [H] Packaging lambda code ..."
# Relative path (not mktemp's /tmp/...) so the native Windows AWS CLI can read
# the zip via fileb:// . Cleaned up by the EXIT trap on $TMPDIR_LOCAL.
WORK="$TMPDIR_LOCAL/lambda-build"
mkdir -p "$WORK"
cat > "$WORK/lambda_function.py" <<EOF
import boto3
import json

sns_client = boto3.client('sns')

def lambda_handler(event, context):
    TOPIC_ARN = '${SNS_TOPIC_ARN}'

    alert_message = (
        "WARNING: Suspicious Access Pattern / Data Leak Signature Detected!\n\n"
        "Security incident event triggers have observed unusual read operations or "
        "high-volume data extractions tracking against target production schemas inside Athena.\n\n"
        "Please review CloudTrail logging activity immediately to trace originating IP coordinates."
    )

    try:
        response = sns_client.publish(
            TopicArn=TOPIC_ARN,
            Message=alert_message,
            Subject='CRITICAL: AWS Cloud Data Leak Alert'
        )
        return {'statusCode': 200, 'body': json.dumps('Alert broadcast dispatched successfully!')}
    except Exception as e:
        print(f"Error executing communication pipeline: {str(e)}")
        raise e
EOF

( cd "$WORK" && zip -q lambda.zip lambda_function.py )

echo ">>> [H] Creating Lambda function: $LAMBDA_NAME ..."
aws lambda create-function --region "$REGION" \
  --function-name "$LAMBDA_NAME" \
  --runtime "$LAMBDA_RUNTIME" \
  --role "$ROLE_ARN" \
  --handler lambda_function.lambda_handler \
  --zip-file "fileb://$WORK/lambda.zip" \
  --timeout 30 \
  --memory-size 128 >/dev/null
save LAMBDA_NAME "$LAMBDA_NAME"

echo
echo "=============================================="
echo " ALL DONE"
echo "=============================================="
echo " VPC          : $VPC_ID"
echo " S3 Bucket    : $S3_BUCKET"
echo " CloudTrail   : $TRAIL_NAME"
echo " RDS Endpoint : $DB_ENDPOINT"
echo " SNS Topic    : $SNS_TOPIC_ARN"
echo " Lambda       : $LAMBDA_NAME"
echo
echo " >>> Confirm the email subscription sent to $SNS_EMAIL <<<"
echo
echo " Test the Lambda:"
echo "   aws lambda invoke --region $REGION --function-name $LAMBDA_NAME out.json && cat out.json"
echo
echo " Connect to DB:"
echo "   mysql -h $DB_ENDPOINT -P 3306 -u $DB_USER -p"
echo
echo " State saved to: $STATE_FILE  (used by teardown.sh)"
