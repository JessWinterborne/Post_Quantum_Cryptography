ROLE_ARN="arn:aws:iam::1234567891011:role/KeyUsageRole"


# Assume the role and capture the temporary credentials
CREDS=$(aws sts assume-role \
  --role-arn "$ROLE_ARN" \
  --role-session-name kms-session)


export AWS_ACCESS_KEY_ID=$(echo "$CREDS" | jq -r .Credentials.AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r .Credentials.SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo "$CREDS" | jq -r .Credentials.SessionToken)

# Run the benchmark commands
npx ts-node benchmark.ts

unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
