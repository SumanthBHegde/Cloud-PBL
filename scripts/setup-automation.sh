#!/usr/bin/env bash
#==============================================================================
# Cloud PBL - Data Leak Monitoring - AUTOMATION LAYER SETUP
#
# Implements the automation layer from SQL_Data_Leak_Detection_AWS.pptx
# (slides 11-14): a scheduled detector that runs the Athena hunt queries
# every 15 minutes and emails an SNS alert ONLY when a rule is triggered.
#
# Creates (on top of an existing setup.sh stack):
#   - IAM role for the detector Lambda (Athena + S3 + SNS + CloudWatch logs)
#   - Lambda "DataLeakDetector" that runs 6 detection queries and alerts on hits
#   - EventBridge (scheduler) rule "DataLeakDetectionSchedule" -> rate(15 minutes)
#
# Reads ./pbl-state.env (from setup.sh) and APPENDS the new resource IDs to it
# so teardown.sh can clean them up.
#
# Usage:
#   chmod +x setup-automation.sh
#   ./setup-automation.sh
#==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECTOR_SRC="$SCRIPT_DIR/detector/lambda_function.py"

STATE_FILE="./pbl-state.env"
if [ ! -f "$STATE_FILE" ]; then
  echo "ERROR: $STATE_FILE not found. Run setup.sh first."
  exit 1
fi
# shellcheck disable=SC1090
source "$STATE_FILE"

save() { echo "$1=\"$2\"" >> "$STATE_FILE"; }

# Local temp dir (relative path so the native Windows AWS CLI can read it via fileb://)
TMPDIR_LOCAL="./.pbl-tmp"
mkdir -p "$TMPDIR_LOCAL"
trap 'rm -rf "$TMPDIR_LOCAL"' EXIT

DETECTOR_NAME="DataLeakDetector-${SUFFIX}"
DETECTOR_ROLE_NAME="${DETECTOR_NAME}-role"
SCHEDULE_RULE_NAME="DataLeakDetectionSchedule-${SUFFIX}"
LAMBDA_RUNTIME="python3.12"

echo "=============================================="
echo " Automation layer setup ($REGION)"
echo " Detector Lambda : $DETECTOR_NAME"
echo " Schedule        : rate(1 minute) (created DISABLED)"
echo "=============================================="

#------------------------------------------------------------------------------
# 0. Enable S3 data-event logging on the trail (DEFENSIVE setup)
#    GetObject is an S3 *data* event; CloudTrail does not log it by default, so
#    the "bulk download" rule would never see anything. We enable it here on the
#    defender side (an attacker would never log their own downloads). Removed
#    automatically when teardown.sh deletes the trail.
#------------------------------------------------------------------------------
echo
echo ">>> [0] Enabling S3 data-event logging on trail $TRAIL_NAME ..."
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
  && echo "    Data events ON (GetObject on $S3_BUCKET is now logged)." \
  || echo "    [WARN] could not enable data events (need cloudtrail:PutEventSelectors)."

#------------------------------------------------------------------------------
# 1. IAM role for the detector Lambda
#------------------------------------------------------------------------------
echo
echo ">>> [1] Creating IAM role for detector Lambda ..."
TRUST='{
  "Version":"2012-10-17",
  "Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]
}'
DETECTOR_ROLE_ARN=$(aws iam create-role --role-name "$DETECTOR_ROLE_NAME" \
  --assume-role-policy-document "$TRUST" \
  --query 'Role.Arn' --output text)
save DETECTOR_ROLE_NAME "$DETECTOR_ROLE_NAME"
save DETECTOR_ROLE_ARN  "$DETECTOR_ROLE_ARN"

aws iam attach-role-policy --role-name "$DETECTOR_ROLE_NAME" \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole

# Inline policy: Athena + Glue (Athena needs Glue catalog) + S3 (log + results) + SNS publish
INLINE_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Athena",
      "Effect": "Allow",
      "Action": [
        "athena:StartQueryExecution",
        "athena:GetQueryExecution",
        "athena:GetQueryResults",
        "athena:GetWorkGroup"
      ],
      "Resource": "*"
    },
    {
      "Sid": "GlueCatalog",
      "Effect": "Allow",
      "Action": [
        "glue:GetTable",
        "glue:GetDatabase",
        "glue:GetPartitions"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3LogAndResults",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"],
      "Resource": [
        "arn:aws:s3:::${S3_BUCKET}",
        "arn:aws:s3:::${S3_BUCKET}/*"
      ]
    },
    {
      "Sid": "SNSPublish",
      "Effect": "Allow",
      "Action": "sns:Publish",
      "Resource": "${SNS_TOPIC_ARN}"
    }
  ]
}
EOF
)
aws iam put-role-policy --role-name "$DETECTOR_ROLE_NAME" \
  --policy-name "DataLeakDetectorPolicy" \
  --policy-document "$INLINE_POLICY"

echo "    role=$DETECTOR_ROLE_ARN"
echo "    Waiting 15s for IAM propagation ..."
sleep 15

#------------------------------------------------------------------------------
# 2. Detector Lambda code
#    The code lives in scripts/detector/lambda_function.py (a real file so
#    teammates can edit it and redeploy via scripts/update-detector.sh). Its
#    config (REGION / S3_BUCKET / SNS_TOPIC_ARN / DETECT_WINDOW_MIN) is passed as
#    Lambda environment variables in step 3, not baked into the code.
#------------------------------------------------------------------------------
echo
echo ">>> [2] Packaging detector Lambda code (from $DETECTOR_SRC) ..."
if [ ! -f "$DETECTOR_SRC" ]; then
  echo "ERROR: detector source not found: $DETECTOR_SRC"
  exit 1
fi
WORK="$TMPDIR_LOCAL/detector-build"
mkdir -p "$WORK"
cp "$DETECTOR_SRC" "$WORK/lambda_function.py"

( cd "$WORK" && zip -q lambda.zip lambda_function.py )

#------------------------------------------------------------------------------
# 3. Create the detector Lambda
#------------------------------------------------------------------------------
echo
echo ">>> [3] Creating detector Lambda: $DETECTOR_NAME ..."
aws lambda create-function --region "$REGION" \
  --function-name "$DETECTOR_NAME" \
  --runtime "$LAMBDA_RUNTIME" \
  --role "$DETECTOR_ROLE_ARN" \
  --handler lambda_function.lambda_handler \
  --zip-file "fileb://$WORK/lambda.zip" \
  --timeout 120 \
  --memory-size 256 \
  --environment "Variables={REGION=$REGION,S3_BUCKET=$S3_BUCKET,SNS_TOPIC_ARN=$SNS_TOPIC_ARN,DETECT_WINDOW_MIN=20}" >/dev/null
save DETECTOR_NAME "$DETECTOR_NAME"
DETECTOR_ARN=$(aws lambda get-function --region "$REGION" \
  --function-name "$DETECTOR_NAME" --query 'Configuration.FunctionArn' --output text)
echo "    $DETECTOR_ARN"

#------------------------------------------------------------------------------
# 4. EventBridge schedule -> invoke detector every 1 minute
#    Created DISABLED on purpose: the detector is stateless and re-alerts on the
#    same historical logs every cycle, so an always-on 1-minute rule would email
#    continuously. Enable it only around a demo:
#      aws events enable-rule  --region "$REGION" --name "$SCHEDULE_RULE_NAME"
#      aws events disable-rule --region "$REGION" --name "$SCHEDULE_RULE_NAME"
#------------------------------------------------------------------------------
echo
echo ">>> [4] Creating EventBridge rule: $SCHEDULE_RULE_NAME (rate 1 min, DISABLED) ..."
RULE_ARN=$(aws events put-rule --region "$REGION" \
  --name "$SCHEDULE_RULE_NAME" \
  --schedule-expression "rate(1 minute)" \
  --state DISABLED \
  --description "Runs DataLeakDetector every 1 minute (enable around a demo)" \
  --query 'RuleArn' --output text)
save SCHEDULE_RULE_NAME "$SCHEDULE_RULE_NAME"

# allow EventBridge to invoke the Lambda
aws lambda add-permission --region "$REGION" \
  --function-name "$DETECTOR_NAME" \
  --statement-id "eventbridge-invoke-${SUFFIX}" \
  --action "lambda:InvokeFunction" \
  --principal events.amazonaws.com \
  --source-arn "$RULE_ARN" >/dev/null

aws events put-targets --region "$REGION" \
  --rule "$SCHEDULE_RULE_NAME" \
  --targets "Id=detector,Arn=$DETECTOR_ARN" >/dev/null
echo "    Rule wired -> $DETECTOR_NAME (currently DISABLED)"

echo
echo "=============================================="
echo " AUTOMATION LAYER READY"
echo "=============================================="
echo " The DataLeakDetector runs the 6 SQL rules and emails the SNS topic"
echo " ONLY when a rule fires. The 1-minute schedule is DISABLED for now."
echo
echo " Enable automatic detection (do this ~2 min before a demo):"
echo "   aws events enable-rule  --region $REGION --name $SCHEDULE_RULE_NAME"
echo " Disable it again afterwards:"
echo "   aws events disable-rule --region $REGION --name $SCHEDULE_RULE_NAME"
echo
echo " Or run one detection cycle by hand right now:"
echo "   aws lambda invoke --region $REGION --function-name $DETECTOR_NAME out.json && cat out.json"
echo
echo " New resource IDs appended to $STATE_FILE (teardown.sh will remove them)."
