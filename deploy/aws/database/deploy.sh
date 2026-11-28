#!/usr/bin/env bash
# Creates or updates the Risk Runner RDS database (template.yaml next to this script) and stores
# its connection URL in Parameter Store as /risk-runner/RISK_RUNNER_DATABASE_URL.
# Runs in .github/workflows/deploy-aws.yml on every deploy (a no-op when nothing changed), or in
# AWS CloudShell. Creating the database takes about 10 minutes.
#
# Environment: AWS_REGION and INSTANCE_ID (the EC2 instance) are required.
#              STACK_NAME (default risk-runner-db), PARAM_PREFIX (default /risk-runner)
set -euo pipefail
cd "$(dirname "$0")"

: "${AWS_REGION:?set AWS_REGION}"
: "${INSTANCE_ID:?set INSTANCE_ID to the EC2 instance ID}"
export AWS_DEFAULT_REGION="$AWS_REGION" AWS_PAGER=""
PREFIX="${PARAM_PREFIX:-/risk-runner}"
STACK="${STACK_NAME:-risk-runner-db}"

mask() { [ -n "${GITHUB_ACTIONS:-}" ] && echo "::add-mask::$1" || true; }
get_param() {
  aws ssm get-parameter --with-decryption --name "$PREFIX/$1" --query Parameter.Value --output text 2>/dev/null || true
}
put_param() {
  aws ssm put-parameter --type SecureString --overwrite --name "$PREFIX/$1" --value "$2" >/dev/null
}

echo "Looking up instance $INSTANCE_ID"
read -r VPC_ID APP_SG < <(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].[VpcId, SecurityGroups[0].GroupId]' --output text)
# RDS needs subnets in at least two availability zones. Use one subnet per zone in the VPC.
SUBNETS="$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" \
  --query 'Subnets[].[AvailabilityZone, SubnetId]' --output text | sort -u -k1,1 | awk '{print $2}' | paste -sd, -)"
if [ "$(tr ',' '\n' <<<"$SUBNETS" | wc -l)" -lt 2 ]; then
  echo "VPC $VPC_ID needs subnets in at least two availability zones for RDS" >&2
  exit 1
fi
echo "VPC $VPC_ID, subnets $SUBNETS, instance security group $APP_SG"

PASSWORD="$(get_param RDS_MASTER_PASSWORD)"
if [ -z "$PASSWORD" ]; then
  echo "Generating the database password ($PREFIX/RDS_MASTER_PASSWORD)"
  PASSWORD="$(openssl rand -hex 24)"
  put_param RDS_MASTER_PASSWORD "$PASSWORD"
fi
mask "$PASSWORD"

echo "Deploying stack $STACK (the first run creates the database and takes about 10 minutes)"
aws cloudformation deploy --template-file template.yaml --stack-name "$STACK" --no-fail-on-empty-changeset \
  --parameter-overrides "VpcId=$VPC_ID" "SubnetIds=$SUBNETS" "AppSecurityGroupId=$APP_SG" "MasterPassword=$PASSWORD"

ENDPOINT="$(aws cloudformation describe-stacks --stack-name "$STACK" \
  --query "Stacks[0].Outputs[?OutputKey=='Endpoint'].OutputValue" --output text)"
URL="postgresql+psycopg://risk:$PASSWORD@$ENDPOINT:5432/risk_runner?sslmode=require"
mask "$URL"
if [ "$(get_param RISK_RUNNER_DATABASE_URL)" != "$URL" ]; then
  echo "Storing $PREFIX/RISK_RUNNER_DATABASE_URL"
  put_param RISK_RUNNER_DATABASE_URL "$URL"
fi
echo "Database ready at $ENDPOINT"
