#!/usr/bin/env bash
# Runs a shell command on the EC2 instance through SSM Run Command, waits for it and prints its
# output. Used by .github/workflows/deploy-aws.yml (no SSH needed).
# Usage: INSTANCE_ID=i-... ssm-run.sh "<comment>" "<command>"
set -euo pipefail
: "${INSTANCE_ID:?set INSTANCE_ID}"
comment="$1" command="$2"

params=$(jq -n --arg c "$command" '{commands: [$c], executionTimeout: ["1800"]}')
id=$(aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name AWS-RunShellScript \
  --comment "$comment" \
  --parameters "$params" \
  --query Command.CommandId --output text)
echo "SSM command $id"

status=Pending
for _ in $(seq 1 180); do
  sleep 10
  status=$(aws ssm get-command-invocation --command-id "$id" --instance-id "$INSTANCE_ID" \
    --query Status --output text 2>/dev/null || echo Pending)
  case "$status" in Success|Failed|Cancelled|TimedOut|Undeliverable|Terminated) break ;; esac
done

echo "::group::Server output"
aws ssm get-command-invocation --command-id "$id" --instance-id "$INSTANCE_ID" \
  --query '[StandardOutputContent, StandardErrorContent]' --output text || true
echo "::endgroup::"
echo "Status: $status"
[ "$status" = Success ]
