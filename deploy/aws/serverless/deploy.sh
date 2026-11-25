#!/usr/bin/env bash
# Builds and deploys the serverless ingest stack (template.yaml next to this script).
# Runs in AWS CloudShell, on your machine, or in .github/workflows/deploy-aws.yml.
# Needs the AWS CLI v2 and uv (CloudShell: curl -LsSf https://astral.sh/uv/install.sh | sh).
#
# Reads from Parameter Store (same /risk-runner/* parameters the server uses):
#   RISK_RUNNER_DATABASE_URL, RISK_RUNNER_INGEST_TOKEN
# Finds the VPC, subnets and security group from the RDS instance.
#
# Environment: AWS_REGION (required), DB_INSTANCE_ID (default risk-runner),
#              STACK_NAME (default risk-runner-ingest), PARAM_PREFIX (default /risk-runner)
set -euo pipefail
cd "$(dirname "$0")"

: "${AWS_REGION:?set AWS_REGION, e.g. AWS_REGION=us-east-2 $0}"
export AWS_DEFAULT_REGION="$AWS_REGION" AWS_PAGER=""
PREFIX="${PARAM_PREFIX:-/risk-runner}"
STACK="${STACK_NAME:-risk-runner-ingest}"
DB_ID="${DB_INSTANCE_ID:-risk-runner}"
BACKEND="$(cd ../../../backend && pwd)"
BUILD=.build

param() {
  aws ssm get-parameter --with-decryption --name "$PREFIX/$1" --query Parameter.Value --output text 2>/dev/null ||
    { echo "Missing parameter $PREFIX/$1 in $AWS_REGION" >&2; exit 1; }
}
DATABASE_URL="$(param RISK_RUNNER_DATABASE_URL)"
INGEST_TOKEN="$(param RISK_RUNNER_INGEST_TOKEN)"

echo "Looking up RDS instance $DB_ID"
db_query() { aws rds describe-db-instances --db-instance-identifier "$DB_ID" --query "DBInstances[0].$1" --output text; }
VPC_ID="$(db_query DBSubnetGroup.VpcId)"
DB_SG="$(db_query 'VpcSecurityGroups[0].VpcSecurityGroupId')"
SUBNETS="$(db_query 'DBSubnetGroup.Subnets[].SubnetIdentifier' | tr -s '\t ' ',')"
ROUTE_TABLES="$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$VPC_ID" \
  --query 'RouteTables[].RouteTableId' --output text | tr -s '\t ' ',')"

# Only one S3 gateway endpoint per route table is allowed. Reuse one that this stack didn't create.
count_endpoints() {
  aws ec2 describe-vpc-endpoints --filters "Name=vpc-id,Values=$VPC_ID" \
    "Name=service-name,Values=com.amazonaws.$AWS_REGION.s3" "Name=vpc-endpoint-type,Values=Gateway" "$@" \
    --query 'length(VpcEndpoints)' --output text
}
others=$(( $(count_endpoints) - $(count_endpoints "Name=tag:aws:cloudformation:stack-name,Values=$STACK") ))
CREATE_S3_ENDPOINT=$([ "$others" -gt 0 ] && echo false || echo true)
echo "VPC $VPC_ID, subnets $SUBNETS, database SG $DB_SG, create S3 endpoint: $CREATE_S3_ENDPOINT"

echo "Building the Lambda package"
rm -rf "$BUILD" && mkdir -p "$BUILD/ingest"
(cd "$BACKEND" && uv export --frozen --no-dev --no-hashes --no-emit-project --quiet) > "$BUILD/requirements.txt"
uv pip install --quiet --target "$BUILD/ingest" --python-version 3.12 \
  --python-platform x86_64-manylinux2014 --only-binary :all: -r "$BUILD/requirements.txt"
cp -r "$BACKEND/src/risk_runner" "$BUILD/ingest/"
find "$BUILD/ingest" -name __pycache__ -prune -exec rm -rf {} +

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
ARTIFACTS="risk-runner-artifacts-$ACCOUNT_ID-$AWS_REGION"
if ! aws s3api head-bucket --bucket "$ARTIFACTS" 2>/dev/null; then
  echo "Creating artifact bucket $ARTIFACTS"
  if [ "$AWS_REGION" = us-east-1 ]; then
    aws s3api create-bucket --bucket "$ARTIFACTS" >/dev/null
  else
    aws s3api create-bucket --bucket "$ARTIFACTS" --create-bucket-configuration "LocationConstraint=$AWS_REGION" >/dev/null
  fi
  aws s3api put-public-access-block --bucket "$ARTIFACTS" --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
fi

echo "Deploying stack $STACK"
aws cloudformation package --template-file template.yaml --s3-bucket "$ARTIFACTS" --s3-prefix "$STACK" \
  --output-template-file "$BUILD/packaged.yaml" >/dev/null
aws cloudformation deploy --template-file "$BUILD/packaged.yaml" --stack-name "$STACK" \
  --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --no-fail-on-empty-changeset \
  --parameter-overrides \
    "VpcId=$VPC_ID" "SubnetIds=$SUBNETS" "RouteTableIds=$ROUTE_TABLES" \
    "CreateS3Endpoint=$CREATE_S3_ENDPOINT" "DatabaseSecurityGroupId=$DB_SG" \
    "DatabaseUrl=$DATABASE_URL" "IngestToken=$INGEST_TOKEN"

URL="$(aws cloudformation describe-stacks --stack-name "$STACK" \
  --query "Stacks[0].Outputs[?OutputKey=='IngestUrl'].OutputValue" --output text)"
echo "Checking $URL"
code="$(curl -s -o /dev/null -w '%{http_code}' "$URL/uploads/00000000000000000000000000000000")"
if [ "$code" != 401 ]; then
  echo "Expected 401 from the ingest endpoint without a token, got $code" >&2
  exit 1
fi
echo "Deployed. Ingest URL: $URL"
