#!/usr/bin/env bash
#==============================================================================
# Cloud PBL - Update the DataLeakDetector Lambda (code + config) IN PLACE
#
# For teammates: to change the detection logic, edit
#     scripts/detector/lambda_function.py
# then run this script. It repackages that file and pushes it to the existing
# DataLeakDetector Lambda. NO infrastructure is recreated - the IAM role,
# EventBridge schedule, SNS topic, and Athena table are all left untouched.
#
# It also (re)applies the Lambda's environment variables so the function keeps
# working even if they were not set before:
#     REGION, S3_BUCKET, SNS_TOPIC_ARN, DETECT_WINDOW_MIN
# Override the lookback window with e.g.  DETECT_WINDOW_MIN=30 ./update-detector.sh
#
# Usage:
#   ./scripts/update-detector.sh
#==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DETECTOR_SRC="$SCRIPT_DIR/detector/lambda_function.py"
STATE_FILE="$PROJECT_ROOT/pbl-state.env"

# Run from the project root so the native Windows AWS CLI can read the zip via a
# relative fileb:// path (it cannot read Git-Bash /d/... style absolute paths).
cd "$PROJECT_ROOT"

if [ ! -f "$STATE_FILE" ]; then
  echo "ERROR: $STATE_FILE not found. Run scripts/setup.sh first."
  exit 1
fi
# shellcheck disable=SC1090
source "$STATE_FILE"

if [ -z "${DETECTOR_NAME:-}" ]; then
  echo "ERROR: DETECTOR_NAME not in $STATE_FILE. Deploy it first:"
  echo "  ./scripts/setup-automation.sh"
  exit 1
fi
if [ ! -f "$DETECTOR_SRC" ]; then
  echo "ERROR: detector source not found: $DETECTOR_SRC"
  exit 1
fi

DETECT_WINDOW_MIN="${DETECT_WINDOW_MIN:-20}"

TMPDIR_LOCAL="./.pbl-tmp"
mkdir -p "$TMPDIR_LOCAL"
trap 'rm -rf "$TMPDIR_LOCAL"' EXIT

echo "=============================================="
echo " Updating detector Lambda: $DETECTOR_NAME"
echo " Source : $DETECTOR_SRC"
echo " Window : ${DETECT_WINDOW_MIN} minutes"
echo "=============================================="

# --- package the code --------------------------------------------------------
WORK="$TMPDIR_LOCAL/detector-build"
mkdir -p "$WORK"
cp "$DETECTOR_SRC" "$WORK/lambda_function.py"
( cd "$WORK" && zip -q lambda.zip lambda_function.py )

# --- 1. (re)apply environment variables, then wait for the update to settle --
# Config and code updates cannot run at the same time, so we wait between them.
echo ">>> [1] Applying environment variables ..."
aws lambda update-function-configuration --region "$REGION" \
  --function-name "$DETECTOR_NAME" \
  --environment "Variables={REGION=$REGION,S3_BUCKET=$S3_BUCKET,SNS_TOPIC_ARN=$SNS_TOPIC_ARN,DETECT_WINDOW_MIN=$DETECT_WINDOW_MIN}" >/dev/null
aws lambda wait function-updated --region "$REGION" --function-name "$DETECTOR_NAME"

# --- 2. push the new code ----------------------------------------------------
echo ">>> [2] Uploading new code ..."
aws lambda update-function-code --region "$REGION" \
  --function-name "$DETECTOR_NAME" \
  --zip-file "fileb://$WORK/lambda.zip" >/dev/null
aws lambda wait function-updated --region "$REGION" --function-name "$DETECTOR_NAME"

echo
echo "=============================================="
echo " DETECTOR UPDATED"
echo "=============================================="
echo " Test it now (runs the 6 rules, emails on a match):"
echo "   aws lambda invoke --region $REGION --function-name $DETECTOR_NAME out.json && cat out.json"
