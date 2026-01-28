#!/usr/bin/env bash
set -euo pipefail

# ---- Required env vars ----
STACK_NAME="aws-encryption-latency-benchmarking"
AWS_REGION="eu-west-2"
S3_BUCKET_ARN="arn:aws:s3:::pqc-code-bucket"
S3_BUCKET_NAME="pqc-code-bucket"
KEY_USER_ARN="arn:aws:iam::1234567891011:user/pqc-experiments-user-1"
export NPM_CONFIG_IGNORE_SCRIPTS=true

# Clean build artifacts
rm -rf dist/

# Build + zip
npm run package

# Upload zip
VERSION_ID=$(
  aws s3api put-object \
    --bucket "$S3_BUCKET_NAME" \
    --key "test-aws-encryption-latency/function.zip" \
    --body "dist/function.zip" \
    --region "$AWS_REGION" \
    --query VersionId \
    --output text
)


aws cloudformation deploy \
  --stack-name "${STACK_NAME}" \
  --template-file template.yaml \
  --region "${AWS_REGION}" \
  --parameter-overrides \
    TrustedPrincipal="${KEY_USER_ARN}" \
    KeyAdminArn="${KEY_USER_ARN}" \
    LambdaCodeVersion="$VERSION_ID" \
    LambdaMemorySize="1024" \
  --capabilities CAPABILITY_NAMED_IAM 

echo "Deployed zip and updated stack ${STACK_NAME} in region ${AWS_REGION}."
