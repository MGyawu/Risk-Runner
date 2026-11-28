#!/usr/bin/env bash
# One-time (and after-merge) setup of what the Deploy to AWS workflow is allowed to do. GitHub
# can't grant itself AWS permissions, so run this yourself in AWS CloudShell:
#
#   AWS_REGION=us-east-2 INSTANCE_ID=i-0abc... GITHUB_OWNER=you ./deploy/aws/bootstrap-permissions.sh
#
# It fills in the account ID, region, instance ID and GitHub IDs itself, then:
#   - sets the deploy role's trust policy: workflows on `main` (plus BRANCH, if given) of
#     GITHUB_OWNER/Risk-Runner may assume it;
#   - attaches three inline policies: SSM deploy to the instance, the RDS stack, the Lambda stack.
#
# BRANCH=feat/serverless-ingest also lets that branch deploy, for trying it before merging.
# After merging, run it again without BRANCH so only `main` can deploy.
#
# Optional: ROLE_NAME (default RiskRunnerGitHubDeploy), REPO (default Risk-Runner),
#           OWNER_ID and REPO_ID (looked up from the GitHub API when not set; needed for private repos).
set -euo pipefail
cd "$(dirname "$0")"

: "${AWS_REGION:?set AWS_REGION}"
: "${INSTANCE_ID:?set INSTANCE_ID to the EC2 instance ID}"
: "${GITHUB_OWNER:?set GITHUB_OWNER to your GitHub user or organization}"
export AWS_DEFAULT_REGION="$AWS_REGION" AWS_PAGER=""
ROLE_NAME="${ROLE_NAME:-RiskRunnerGitHubDeploy}"
REPO="${REPO:-Risk-Runner}"
BRANCH="${BRANCH:-}"

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
if [ -z "${OWNER_ID:-}" ] || [ -z "${REPO_ID:-}" ]; then
  ids="$(curl -fsS "https://api.github.com/repos/$GITHUB_OWNER/$REPO")" ||
    { echo "Couldn't read $GITHUB_OWNER/$REPO from the GitHub API. For a private repo, set OWNER_ID and REPO_ID." >&2; exit 1; }
  OWNER_ID="$(jq -r .owner.id <<<"$ids")" REPO_ID="$(jq -r .id <<<"$ids")"
fi
aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].InstanceId' --output text >/dev/null ||
  { echo "Instance $INSTANCE_ID not found in $AWS_REGION" >&2; exit 1; }
aws iam get-role --role-name "$ROLE_NAME" --query Role.Arn --output text >/dev/null ||
  { echo "Role $ROLE_NAME not found. Create it first (deploy/aws/README.md, step 9)." >&2; exit 1; }
PROVIDER="arn:aws:iam::$ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$PROVIDER" >/dev/null ||
  { echo "GitHub OIDC provider missing. Create it first (deploy/aws/README.md, step 8)." >&2; exit 1; }

refs=("refs/heads/main")
[ -n "$BRANCH" ] && refs+=("refs/heads/$BRANCH")
subjects="$(for ref in "${refs[@]}"; do
  echo "repo:$GITHUB_OWNER/$REPO:ref:$ref"
  echo "repo:$GITHUB_OWNER@$OWNER_ID/$REPO@$REPO_ID:ref:$ref"
done | jq -R . | jq -s .)"
trust="$(jq --arg p "$PROVIDER" --argjson s "$subjects" '
  .Statement[0].Principal.Federated = $p
  | .Statement[0].Condition.StringEquals["token.actions.githubusercontent.com:sub"] = $s' github-oidc-trust-policy.json)"
aws iam update-assume-role-policy --role-name "$ROLE_NAME" --policy-document "$trust"
echo "Trust policy: workflows on ${refs[*]#refs/heads/} of $GITHUB_OWNER/$REPO can deploy."

fill() { sed -e "s/REGION/$AWS_REGION/g" -e "s/ACCOUNT_ID/$ACCOUNT_ID/g" -e "s/INSTANCE_ID/$INSTANCE_ID/g" "$1"; }
for entry in RiskRunnerDeploySsm:deploy-role-policy.json \
             RiskRunnerDeployDatabase:database/deploy-role-policy.json \
             RiskRunnerDeployIngest:serverless/deploy-role-policy.json; do
  name="${entry%%:*}" file="${entry#*:}"
  policy="$(fill "$file")"
  if grep -qE 'REGION|ACCOUNT_ID|INSTANCE_ID' <<<"$policy"; then
    echo "A placeholder is left in $file" >&2; exit 1
  fi
  aws iam put-role-policy --role-name "$ROLE_NAME" --policy-name "$name" --policy-document "$policy"
  echo "Inline policy $name updated from $file"
done

others="$(aws iam list-role-policies --role-name "$ROLE_NAME" --query 'PolicyNames' --output text | tr '\t' '\n' |
  grep -vxE 'RiskRunnerDeploySsm|RiskRunnerDeployDatabase|RiskRunnerDeployIngest' || true)"
if [ -n "$others" ]; then
  echo "The role also has these inline policies (probably the one pasted by hand in step 9; now redundant):"
  echo "$others" | sed 's/^/  /'
fi
echo "Done. Role ARN: $(aws iam get-role --role-name "$ROLE_NAME" --query Role.Arn --output text)"
