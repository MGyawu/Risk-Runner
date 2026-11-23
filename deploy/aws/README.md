# Deploying Risk Runner to AWS

One EC2 instance runs Caddy (HTTPS), Risk Runner and Postgres with
[docker-compose.aws.yml](../../docker-compose.aws.yml). After a one-time setup, every push to
`main` is tested and deployed by [.github/workflows/deploy-aws.yml](../../.github/workflows/deploy-aws.yml):

```
push to main ─▶ CI tests ─▶ GitHub OIDC token ─▶ AWS role (no stored keys)
                                                     │ SSM Run Command (no SSH)
                                                     ▼
                         EC2: git checkout <sha> ─▶ deploy/deploy.sh
                              reads secrets from SSM Parameter Store (KMS-encrypted)
                              docker compose up --build ─▶ health check
```

Replace these placeholders throughout: `REGION` (e.g. `us-east-1`), `ACCOUNT_ID` (12 digits),
`GITHUB_OWNER` (your GitHub user or org), `INSTANCE_ID` (e.g. `i-0abc…`), and your domain.

## A. One-time setup

### 1. Push Risk-Runner to GitHub
Push to the `main` branch. The deploy job stays skipped until step 10, so pushing early is safe.

### 2. Create the instance role
IAM → Roles → Create role → *AWS service*, use case **EC2**.
- Attach the managed policy **AmazonSSMManagedInstanceCore** (lets SSM manage the instance).
- Name it `RiskRunnerInstance`.
- Open the role → Add permissions → Create inline policy → JSON → paste
  [instance-policy.json](instance-policy.json) with `REGION` and `ACCOUNT_ID` filled in.
  This lets the server read only `/risk-runner/*` parameters.

### 3. Launch the instance
EC2 → Launch instance:
- **AMI:** Ubuntu Server 24.04 LTS. **Type:** t3.small. **Storage:** 20 GB gp3.
- **Key pair:** optional, since you'll connect through Session Manager instead of SSH.
- **Security group:** allow HTTP (80) and HTTPS (443) from anywhere. You don't need port 22.
- **Advanced details → IAM instance profile:** `RiskRunnerInstance`.
- **Advanced details → User data:** paste [user-data.sh](user-data.sh). It installs Docker and the AWS CLI.

Then allocate an **Elastic IP** and associate it with the instance. Note the instance ID.

### 4. Point a hostname at it
Create an A record such as `riskrunner.yourdomain.com` that points to the Elastic IP.
If you have no domain, use `<ip-with-dashes>.sslip.io`, e.g. `3-91-10-20.sslip.io`.

### 5. Store the secrets in Parameter Store
From your machine (AWS CLI signed in to the account), or CloudShell in the console:

```bash
REGION=us-east-1
put() { aws ssm put-parameter --region "$REGION" --type SecureString --overwrite --name "/risk-runner/$1" --value "$2"; }
put DOMAIN riskrunner.yourdomain.com
put POSTGRES_PASSWORD "$(openssl rand -hex 24)"
put RISK_RUNNER_INGEST_TOKEN "$(openssl rand -hex 32)"
put RISK_RUNNER_API_TOKEN "$(openssl rand -hex 32)"
# Optional: Claude analysis
# put RISK_RUNNER_AI_ENABLED true
# put ANTHROPIC_API_KEY sk-ant-...
```

Every `/risk-runner/<NAME>` parameter becomes `NAME=value` in the server's `.env`, so any
`RISK_RUNNER_*` setting can be added the same way. Avoid `$` in values (Docker Compose expands it).
To read a token back later (for GitHub or the dashboard):
`aws ssm get-parameter --region "$REGION" --with-decryption --name /risk-runner/RISK_RUNNER_INGEST_TOKEN --query Parameter.Value --output text`

### 6. Clone the repo on the server
Connect with EC2 → the instance → **Connect → Session Manager**, then:

```bash
sudo -iu ubuntu
```

If the repo is **private**, give the server a read-only deploy key:

```bash
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519 && cat ~/.ssh/id_ed25519.pub
```

Add the printed key in GitHub → Risk-Runner → Settings → Deploy keys (leave write access off). Then:

```bash
git clone git@github.com:GITHUB_OWNER/Risk-Runner.git ~/Risk-Runner
```

(For a public repo: `git clone https://github.com/GITHUB_OWNER/Risk-Runner.git ~/Risk-Runner`.)

### 7. First deploy by hand
This checks the server setup before automation gets involved. It's still in the Session Manager shell, as `ubuntu`:

```bash
cd ~/Risk-Runner && AWS_REGION=us-east-1 ./deploy/deploy.sh
```

It should end with `Deployed.` Then open `https://<your-domain>/api/health`. The first certificate
can take a minute.

### 8. Let GitHub sign in to AWS (OIDC provider, once per account)
IAM → Identity providers → Add provider → **OpenID Connect**:
- Provider URL: `https://token.actions.githubusercontent.com`
- Audience: `sts.amazonaws.com`

### 9. Create the deploy role
IAM → Roles → Create role → **Web identity** → provider `token.actions.githubusercontent.com`,
audience `sts.amazonaws.com`. Finish creating it as `RiskRunnerGitHubDeploy` without adding permissions, then:
- **Trust relationships → Edit:** paste [github-oidc-trust-policy.json](github-oidc-trust-policy.json)
  with `ACCOUNT_ID` and `GITHUB_OWNER` filled in. Only workflows running on `main` of your
  Risk-Runner repo can assume it.
- **Add permissions → Create inline policy → JSON:** paste [deploy-role-policy.json](deploy-role-policy.json)
  with `REGION`, `ACCOUNT_ID` and `INSTANCE_ID` filled in. It can only send commands to this one instance.

Copy the role ARN.

### 10. Configure the GitHub repo
These are *variables*, not secrets. None of them is sensitive:

```bash
gh variable set AWS_REGION --body us-east-1
gh variable set AWS_DEPLOY_ROLE_ARN --body arn:aws:iam::ACCOUNT_ID:role/RiskRunnerGitHubDeploy
gh variable set EC2_INSTANCE_ID --body i-0123456789abcdef0
gh variable set DOMAIN --body riskrunner.yourdomain.com
```

(Or Settings → Secrets and variables → Actions → Variables.)

## B. Deploying

- Push to `main`. **CI** runs the tests, then **Deploy to AWS** deploys that exact commit and runs a health check.
- To redeploy without a code change (e.g. after changing a parameter), go to Actions → Deploy to AWS → **Run workflow**.
- The server's output appears in the "Server output" group of the deploy step.
- To rotate a secret: `put` the new value, run the workflow, then update every place that uses it
  (GitHub secrets in scanned repos, the dashboard's Token button).

Open `https://<your-domain>`, click **Token**, and paste the `RISK_RUNNER_API_TOKEN` value.

## C. Field test with OWASP Juice Shop

Juice Shop is deliberately vulnerable, so don't host it on AWS. The workflow runs it only
inside the GitHub runner and scans `localhost`.

1. Fork https://github.com/juice-shop/juice-shop and enable workflows in the fork's **Actions** tab.
2. Add the upload action and the workflow to the fork:
   ```bash
   git clone https://github.com/GITHUB_OWNER/juice-shop.git && cd juice-shop
   mkdir -p .github/actions/risk-runner-upload
   cp ~/GitHub/Risk-Runner/action/action.yml .github/actions/risk-runner-upload/
   cp ~/GitHub/Risk-Runner/examples/juice-shop-security-scan.yml .github/workflows/risk-runner.yml
   ```
3. Add secrets to the fork: `RISK_RUNNER_URL` = `https://<your-domain>`, and `RISK_RUNNER_TOKEN` = the
   `RISK_RUNNER_INGEST_TOKEN` value from Parameter Store:
   ```bash
   gh secret set RISK_RUNNER_URL --repo GITHUB_OWNER/juice-shop
   gh secret set RISK_RUNNER_TOKEN --repo GITHUB_OWNER/juice-shop
   ```
4. Commit and push to `master`. Semgrep (SAST), Trivy (SCA) and ZAP baseline (DAST) run and upload.

## D. What to check

1. **Findings:** `GITHUB_OWNER/juice-shop` appears with findings from all three scanners. Wait a minute or two for CVE/EPSS/KEV enrichment.
2. **Business context:** set criticality 5, internet-facing, restricted data, "PCI", revenue-impacting, then save. Scores should rise.
3. **Ranking:** do Juice Shop's known SQL injection, XSS and auth problems rank near the top? If not, tune the weights in `scoring.py`.
4. **Claude analysis (optional):** add the AI parameters (step 5), rerun the deploy, then click **Run analysis**.
5. **Fixed findings:** remove a vulnerable dependency in the fork and push. Those findings should be marked fixed.

## E. Costs and cleanup

A t3.small with 20 GB costs roughly $15–20 a month, and an Elastic IP is billed while it exists.
When you're done:
- Terminate the instance and release the Elastic IP.
- Delete the `/risk-runner/*` parameters and both IAM roles.
- Unset `EC2_INSTANCE_ID` so the deploy job skips again.
