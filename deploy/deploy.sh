#!/usr/bin/env bash
# Runs on the EC2 instance (called by .github/workflows/deploy-aws.yml through SSM, or by hand).
# Writes .env from SSM Parameter Store, then rebuilds and restarts the stack.
set -euo pipefail
cd "$(dirname "$0")/.."

PREFIX="${PARAM_PREFIX:-/risk-runner}"
COMPOSE=(docker compose -f docker-compose.aws.yml)

echo "Loading configuration from SSM Parameter Store ($PREFIX/*)"
umask 077
aws ssm get-parameters-by-path --path "$PREFIX" --recursive --with-decryption \
  --query 'Parameters[*].[Name,Value]' --output text |
  while IFS=$'\t' read -r name value; do
    printf '%s=%s\n' "${name##*/}" "$value"
  done > .env.new

for key in DOMAIN POSTGRES_PASSWORD RISK_RUNNER_INGEST_TOKEN RISK_RUNNER_API_TOKEN; do
  if ! grep -q "^$key=." .env.new; then
    echo "Missing parameter $PREFIX/$key" >&2
    rm -f .env.new
    exit 1
  fi
done
mv .env.new .env

echo "Building and starting $(git rev-parse --short HEAD)"
"${COMPOSE[@]}" up -d --build --remove-orphans
docker image prune -f >/dev/null

echo "Waiting for the app to report healthy"
for _ in $(seq 1 30); do
  if "${COMPOSE[@]}" exec -T risk-runner python3 -c \
    "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health', timeout=3)" 2>/dev/null; then
    echo "Deployed."
    exit 0
  fi
  sleep 3
done
echo "App did not become healthy" >&2
"${COMPOSE[@]}" logs --tail 80 risk-runner >&2
exit 1
