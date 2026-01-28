#!/usr/bin/env bash
set -euo pipefail

# ---- Required env vars ----
STACK_NAME="aws-encryption-latency-benchmarking"
AWS_REGION="eu-west-2"
S3_BUCKET_ARN="arn:aws:s3:::pqc-code-bucket"
S3_BUCKET_NAME="pqc-code-bucket"
KEY_USER_ARN="arn:aws:iam::1234567891011:user/pqc-experiments-user-1"
export NPM_CONFIG_IGNORE_SCRIPTS=true

#!/usr/bin/env bash
set -euo pipefail

# Where you want results saved:
OUTPUT_DIR="./automated_results/token_encryption_latency"

# Memory sizes to test:
# MEMORY_SIZES=(128 135 150 175 200 225 250 275 300 325 350 375 400 450 512 600 700)
MEMORY_SIZES=(128 300 512 1024 2048)


# CloudFormation output key that contains the function invoke URL:
# Update this to match your template OutputKey exactly.
INVOKE_URL_OUTPUT_KEY="FunctionUrl"


mkdir -p "$OUTPUT_DIR"

# sanity checks
if [[ ! -d "$OUTPUT_DIR" ]]; then
  echo "ERROR: OUTPUT_DIR is not a directory: $OUTPUT_DIR" >&2
  exit 1
fi
if [[ ! -w "$OUTPUT_DIR" ]]; then
  echo "ERROR: OUTPUT_DIR is not writable: $OUTPUT_DIR" >&2
  echo "Try: chmod u+w \"$OUTPUT_DIR\"  or choose a different path." >&2
  exit 1
fi


# Clean build artifacts
rm -rf dist/

# Build + zip
npm run package

VERSION_ID=$(
  aws s3api put-object \
    --bucket "$S3_BUCKET_NAME" \
    --key "test-aws-encryption-latency/function.zip" \
    --body "dist/function.zip" \
    --region "$AWS_REGION" \
    --query VersionId \
    --output text
)


# Helper to read invoke URL from stack outputs
get_invoke_url() {
  aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$AWS_REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='${INVOKE_URL_OUTPUT_KEY}'].OutputValue | [0]" \
    --output text
}

for MEM in "${MEMORY_SIZES[@]}"; do
  echo "============================================================"
  echo "==> Deploying stack for LambdaMemorySize=${MEM} ..."

  aws cloudformation deploy \
    --stack-name "$STACK_NAME" \
    --template-file template.yaml \
    --region "$AWS_REGION" \
    --parameter-overrides \
      TrustedPrincipal="${KEY_USER_ARN}" \
      KeyAdminArn="${KEY_USER_ARN}" \
      LambdaCodeVersion="$VERSION_ID" \
      LambdaMemorySize="$MEM" \
    --capabilities CAPABILITY_NAMED_IAM

  echo "==> Stack deployed for memory=${MEM}. Fetching invoke URL from Outputs (key=${INVOKE_URL_OUTPUT_KEY})..."

  INVOKE_URL="$(get_invoke_url)"

  if [[ -z "${INVOKE_URL}" || "${INVOKE_URL}" == "None" ]]; then
    echo "ERROR: Could not find an OutputValue for OutputKey '${INVOKE_URL_OUTPUT_KEY}'."
    echo "Tip: List outputs with:"
    echo "  aws cloudformation describe-stacks --stack-name \"$STACK_NAME\" --region \"$AWS_REGION\" --query 'Stacks[0].Outputs' --output table"
    exit 1
  fi

  echo "==> Invoke URL: $INVOKE_URL"
  echo "==> Calling endpoint (may take > 1 minute)..."

  OUT_FILE="${OUTPUT_DIR}/${MEM}.json"


  # Make initial call to lambda to pre-warm
    HTTP_CODE="$(
    curl -sS -L \
      --max-time 300 \
      -w "%{http_code}" \
      "$INVOKE_URL"
  )"

  # Make an empty GET request and save ONLY the body to file.
  # -L follows redirects
  # --max-time allows long-running requests
  # --retry helps transient failures (optional)
  HTTP_CODE="$(
    curl -sS -L \
      --max-time 300 \
      --retry 2 \
      --retry-delay 2 \
      -o "$OUT_FILE" \
      -w "%{http_code}" \
      "$INVOKE_URL"
  )"

  echo "==> HTTP status: $HTTP_CODE"
  echo "==> Saved response body to: $OUT_FILE"
done

echo
echo "Done. Results written to: $OUTPUT_DIR"
