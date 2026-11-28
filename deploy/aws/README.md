# Deploying Risk Runner to AWS

One EC2 instance runs Caddy (HTTPS) and the Risk Runner web app with
[docker-compose.aws.yml](../../docker-compose.aws.yml). The data lives in **Amazon RDS for
PostgreSQL**, so it survives the instance. Optionally, scanner reports are ingested by **Lambda**
instead of the web server ([part H](#h-serverless-ingestion-lambda)). After a one-time setup,
every push to `main` is tested and deployed by [.github/workflows/deploy-aws.yml](../../.github/workflows/deploy-aws.yml):

```
push to main ─▶ CI tests ─▶ GitHub OIDC token ─▶ AWS role (no stored keys)
                                                     │ SSM Run Command (no SSH)
                                                     ▼
                         EC2: git checkout <sha> ─▶ deploy/deploy.sh
                              reads secrets from SSM Parameter Store (KMS-encrypted)
                              docker compose up --build ─▶ health check

GitHub Actions scans ──▶ EC2 web app ─────────────────────────┐
         or (part H) ──▶ API Lambda ─▶ S3 ─▶ SQS ─▶ Lambda ────┴─▶ RDS PostgreSQL
```

**Already running the older single-server setup** (Postgres in a container on the instance)?
Follow [I. Moving an existing deployment to RDS and Lambda](#i-moving-an-existing-deployment-to-rds-and-lambda)
instead of part A.

Contents: [Lessons learned](#lessons-learned-things-to-watch-out-for) ·
[A. One-time setup](#a-one-time-setup) ·
[B. Deploying](#b-deploying) ·
[C. Connecting repositories to scan](#c-connecting-repositories-to-scan) ·
[D. Field test with Juice Shop](#d-field-test-with-owasp-juice-shop) ·
[E. What to check](#e-what-to-check) ·
[F. Troubleshooting](#f-troubleshooting) ·
[G. Pausing, tearing down and rebuilding](#g-pausing-tearing-down-and-rebuilding) ·
[H. Serverless ingestion](#h-serverless-ingestion-lambda) ·
[I. Moving an existing deployment](#i-moving-an-existing-deployment-to-rds-and-lambda)

## Before you start

### Placeholders

Replace these everywhere they appear, in commands and in the JSON policy files:

| Placeholder | Example | Where to find it |
|---|---|---|
| `REGION` | `us-east-2` | Region selector, top right of the AWS console |
| `ACCOUNT_ID` | 12 digits | Account menu, top right of the AWS console |
| `GITHUB_OWNER` | your GitHub user or org | Your repository URL |
| `OWNER_ID`, `REPO_ID` | numeric GitHub IDs | See step 9 |
| `INSTANCE_ID` | `i-0abc…` | EC2 → Instances (after step 3) |
| `YOUR_DOMAIN` | `riskrunner.example.com` | Chosen in step 4 |

Before running a command or saving a policy, check that no placeholder is left in it. A
placeholder left in an IAM policy doesn't cause an error when you save it. The policy just
matches nothing, and AWS later reports AccessDenied.

### Use one region for everything

The instance, the Parameter Store values, both IAM policies, the `AWS_REGION` GitHub variable
and the `AWS_REGION=` in the manual deploy command must all use the same region. CloudShell
runs against whichever region the console is set to, so check the region selector before
running commands there.

### Where each command runs

| Where | Used for |
|---|---|
| **CloudShell** (or your machine with the AWS CLI signed in) | Parameter Store (step 5), IAM checks, troubleshooting |
| **The instance**, through EC2 → Connect → **Session Manager** | Cloning and the first deploy (steps 6–7), container logs |
| **GitHub** (website or `gh`) | Repository variables (step 10) and secrets in scanned repos (section C) |

CloudShell is a separate AWS-hosted machine, not your server. Anything you clone or run there
doesn't affect the instance.

### Lessons learned: things to watch out for

These came up in real deployments. Each one fails quietly or with an unclear message, so check
for them as you go. [F. Troubleshooting](#f-troubleshooting) has the fix for each symptom.

**AWS setup**
- **Region drift.** It's easy to create the instance in one region and the parameters in
  another (CloudShell follows the console's region selector). The deploy then stops with
  *"Missing parameter"*. Pick one region and check it before every command.
- **Placeholders left in policies.** IAM saves a policy that still says `INSTANCE_ID`, `REGION`
  or `ACCOUNT_ID` without complaint. It fails later as AccessDenied. Read each policy back after saving it.
- **The instance role has two parts.** The create wizard only takes the managed policy
  (`AmazonSSMManagedInstanceCore`); the inline parameter policy is added after the role exists.
  The role also has to be **attached to the instance** (IAM instance profile). A role that
  exists but isn't attached gives *"DHMC is not enabled and IAM instance profile is not attached"*.
- **The role name doesn't matter, but the trusted entity does.** The instance role must be
  *AWS service → EC2*, or it won't be offered as an instance profile. Only the deploy role's
  name is referenced anywhere (by the `AWS_DEPLOY_ROLE_ARN` variable).
- **The OIDC provider comes before the deploy role.** Until it exists, the *Web identity*
  wizard has nothing to select.
- **GitHub's OIDC subject format can include numeric IDs.** A trust policy matching only
  `repo:owner/repo:ref:refs/heads/main` can be rejected when GitHub sends
  `repo:owner@OWNER_ID/repo@REPO_ID:…`. The template accepts both. When in doubt, CloudTrail
  shows the exact subject GitHub sent.

**Hostname and HTTPS**
- **Use your own IP in the hostname.** Copying an example sslip.io name into the `DOMAIN`
  parameter makes Caddy request a certificate for someone else's IP. The app deploys fine, but
  HTTPS fails with *"tlsv1 alert internal error"*. The `DOMAIN` parameter and the `DOMAIN`
  variable must be the same hostname.
- **Look up the hostname, not the IP.** `nslookup <ip>` returns AWS's `ec2-….amazonaws.com`
  name, which Let's Encrypt won't issue certificates for. Test `nslookup <hostname> 8.8.8.8`;
  some home and office DNS servers block sslip.io/nip.io names even though the public internet resolves them.
- **A successful deploy doesn't mean HTTPS works.** The app can be healthy while Caddy is still
  failing to get a certificate. The Caddy log shows why.

**Secrets and the server**
- **Generated secrets change every time you run the commands.** Rerunning the step 5b block
  creates new tokens. Rerun only the line you mean to change.
- **Let the scripts own the database settings.** `RDS_MASTER_PASSWORD` and
  `RISK_RUNNER_DATABASE_URL` are written by `deploy/aws/database/deploy.sh`. Changing the password
  in the RDS console, or editing the URL by hand, locks the app out. To change the password, `put`
  a new `RDS_MASTER_PASSWORD` and run the workflow.
- **Don't create the database in the RDS console.** The workflow creates `risk-runner` as a
  CloudFormation stack and fails if a database with that name already exists.
- **Parameters are read only at deploy time.** After changing one, redeploy.
- **Run server commands on the server.** Steps 6–7 run in Session Manager on the instance (the
  prompt shows `ubuntu@ip-…`), not in CloudShell. Paste one command at a time; two commands run
  together produce odd errors, such as git asking for a password on a public repo.

**Scanned repositories**
- **Secrets, not variables.** `RISK_RUNNER_URL` and `RISK_RUNNER_TOKEN` are read as
  `secrets.…`. A variable with the same name arrives empty.
- **The ingest token, not the API token.** The ingest token goes in scanned repos; the API
  token goes in the dashboard. Copy both from the server's region, with no quotes or whitespace.
- **The secrets alone do nothing.** The workflow must write a report file and run the upload step.
- **"Fail on findings" blocks the upload.** `semgrep --error` or Trivy `exit-code: 1` stops the
  job before a later upload step runs. Use `if: always()` or a separate report step.
- **A green upload step can still have failed.** Uploads only warn by default. Read the step
  log, or set `fail-on-error: "true"`.
- **Only the default branch counts.** Pull request and feature branch scans don't change findings.
- **An empty dashboard usually means no token.** Click **Token** and paste the API token.

**Shutting down**
- **Stopping isn't terminating.** A stopped instance keeps its disk and its Elastic IP. The data
  is in RDS, so even a terminated instance doesn't lose findings.
- **A stopped RDS database starts again by itself after 7 days**, and is billed from then on.
- **Disable the deploy workflow before stopping or deleting the instance**, or every push to
  `main` produces a failed deploy. Scanned repos will also show upload warnings until their
  uploads are disabled or the server is back.
- **A new Elastic IP means a new sslip.io/nip.io hostname.** Update the `DOMAIN` parameter, the
  `DOMAIN` variable and `RISK_RUNNER_URL` in each scanned repo.

## A. One-time setup

### 1. Push Risk-Runner to GitHub
Push to the `main` branch. The deploy job stays skipped until step 10, so pushing early is safe.

### 2. Create the instance role
IAM → Roles → Create role → trusted entity type **AWS service**, use case **EC2**.
- In the wizard, attach the managed policy **AmazonSSMManagedInstanceCore**. It lets Session
  Manager and the deploy workflow reach the instance.
- Name it, for example `RiskRunnerInstance`. Nothing depends on the name.
- After the role is created, open it → Add permissions → **Create inline policy** → JSON →
  paste [instance-policy.json](instance-policy.json) with `REGION` and `ACCOUNT_ID` filled in.
  This lets the server read only the `/risk-runner/*` parameters. The wizard only offers
  managed policies, so the inline policy has to be added afterwards.

When you're done, the role's Permissions tab should list both policies.

### 3. Launch the instance
EC2 → Launch instance, in your chosen region:
- **AMI:** Ubuntu Server 24.04 LTS. **Type:** t3.small. **Storage:** 20 GB gp3.
- **Key pair:** optional, since you'll connect through Session Manager instead of SSH.
- **Network:** the default VPC's public subnet is fine. The instance needs outbound internet
  access to reach SSM.
- **Security group:** allow HTTP (80) and HTTPS (443) from anywhere. You don't need port 22.
  Keep the default outbound rule (all traffic).
- **Advanced details → IAM instance profile:** the role from step 2. This is required. If you
  forget it, see [F. Troubleshooting](#f-troubleshooting).
- **Advanced details → User data:** paste [user-data.sh](user-data.sh). It installs Docker and the AWS CLI.

Then give the instance a fixed public IP:
1. EC2 → **Elastic IPs** → **Allocate Elastic IP address** → Allocate (same region).
2. Select it → Actions → **Associate Elastic IP address** → Resource type **Instance** → pick
   your instance. Leave *Private IP address* at its default and leave *Allow reassociation*
   unchecked → Associate.
3. Check that the instance's Details tab now shows the Elastic IP as its *Public IPv4 address*.

Note the instance ID.

### 4. Choose a hostname
Caddy needs a hostname that resolves to the Elastic IP to get a Let's Encrypt certificate.

- **With a domain:** create an A record such as `riskrunner.yourdomain.com` that points to the Elastic IP.
- **Without a domain:** use `<elastic-ip-with-dashes>.sslip.io`. For an IP of `203.0.113.10`,
  that's `203-0-113-10.sslip.io`. You don't need to create any DNS record. `….nip.io` works
  the same way and is a good fallback.

Check it against a public resolver, which is what Let's Encrypt uses:
`nslookup <hostname> 8.8.8.8`. If this works but a plain `nslookup` returns "non-existent
domain", your local network's DNS is blocking these names. The server is unaffected. To use the
dashboard from that network, switch your machine to a public DNS resolver.

Don't use the instance's `ec2-….amazonaws.com` name, because Let's Encrypt won't issue
certificates for it. Also, `nslookup <ip>` performs a reverse lookup and returns that AWS name.
It doesn't test your hostname.

### 5. Create the database and store the secrets

#### 5a. Create the RDS database
In CloudShell (check the region selector). This is the same script the Deploy to AWS workflow
runs, so later deploys keep it up to date:

```bash
git clone https://github.com/GITHUB_OWNER/Risk-Runner.git ~/Risk-Runner
```

```bash
cd ~/Risk-Runner && AWS_REGION=REGION INSTANCE_ID=INSTANCE_ID ./deploy/aws/database/deploy.sh
```

It takes about 10 minutes and ends with `Database ready at …`. It creates the `risk-runner-db`
CloudFormation stack: a db.t4g.micro PostgreSQL 17 database named `risk-runner` in the
instance's VPC, reachable only from the instance's security group, encrypted, with 7-day
backups and deletion protection. It also generates the password and stores
`/risk-runner/RDS_MASTER_PASSWORD` and `/risk-runner/RISK_RUNNER_DATABASE_URL`.

#### 5b. Store the secrets in Parameter Store
In CloudShell:

```bash
REGION=REGION   # your region, e.g. us-east-2
put() { aws ssm put-parameter --region "$REGION" --type SecureString --overwrite --name "/risk-runner/$1" --value "$2"; }
put DOMAIN YOUR_DOMAIN
put RISK_RUNNER_INGEST_TOKEN "$(openssl rand -hex 32)"
put RISK_RUNNER_API_TOKEN "$(openssl rand -hex 32)"
# Optional: Claude analysis
# put RISK_RUNNER_AI_ENABLED true
# put ANTHROPIC_API_KEY sk-ant-...
```

- `openssl rand` generates new random values each time it runs, and nothing is printed.
  Read a value back with
  `aws ssm get-parameter --region "$REGION" --with-decryption --name /risk-runner/<NAME> --query Parameter.Value --output text`.
- **`DOMAIN` must be your real hostname from step 4.** If it's wrong, Caddy requests a
  certificate for a host that isn't your server and HTTPS fails.
- **Don't rerun the whole block later.** It creates new tokens that scanned repos and the
  dashboard don't know about. To change a single value, run just its `put` line.
- Every `/risk-runner/<NAME>` parameter becomes `NAME=value` in the server's `.env`, so any
  `RISK_RUNNER_*` setting can be added the same way. Avoid `$` in values (Docker Compose expands it).
- Check what's stored: `aws ssm get-parameters-by-path --region "$REGION" --path /risk-runner --query 'Parameters[].Name'`.
  This should list at least `DOMAIN`, `RDS_MASTER_PASSWORD`, `RISK_RUNNER_DATABASE_URL`,
  `RISK_RUNNER_INGEST_TOKEN` and `RISK_RUNNER_API_TOKEN`.

### 6. Clone the repo on the server
Connect with EC2 → the instance → **Connect → Session Manager → Connect**. This opens a shell on
the instance itself (not CloudShell). It can take 2–5 minutes after launch before Session
Manager is available. Then switch to the `ubuntu` user:

```bash
sudo -iu ubuntu
```

The prompt should look like `ubuntu@ip-172-…`. Run the following commands one at a time.

For a **public** repo:

```bash
git clone https://github.com/GITHUB_OWNER/Risk-Runner.git ~/Risk-Runner
```

For a **private** repo, give the server a read-only deploy key:

```bash
ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519 && cat ~/.ssh/id_ed25519.pub
```

Add the printed key in GitHub → Risk-Runner → Settings → Deploy keys (leave write access off). Then:

```bash
git clone git@github.com:GITHUB_OWNER/Risk-Runner.git ~/Risk-Runner
```

A public HTTPS clone never asks for a password. If git asks for one, the URL is wrong. A common
cause is two commands pasted onto one line. Press Ctrl+C and retry.

### 7. First deploy by hand
This checks the server setup before automation gets involved. Still in the Session Manager shell, as `ubuntu`:

```bash
cd ~/Risk-Runner && AWS_REGION=REGION ./deploy/deploy.sh
```

The first build takes several minutes. It should end with `Deployed.` Then open
`https://YOUR_DOMAIN/api/health`, which should return `{"status":"ok",…}`. The first certificate
can take a minute or two.

### 8. Let GitHub sign in to AWS (OIDC provider, once per account)
IAM → Identity providers → Add provider → **OpenID Connect**:
- Provider URL: `https://token.actions.githubusercontent.com`
- Audience: `sts.amazonaws.com`

If the console shows a *Get thumbprint* button, click it. If the provider is already listed,
don't add a second one.

### 9. Create the deploy role
IAM → Roles → Create role → trusted entity type **Web identity** → provider
`token.actions.githubusercontent.com` (only listed after step 8), audience `sts.amazonaws.com`.
Some console versions also ask for a GitHub organization, repository and branch. Fill them in
if shown; the policy you paste below replaces whatever the wizard generates. Add no
permissions and create the role as `RiskRunnerGitHubDeploy`. Then:

- **Trust relationships → Edit trust policy:** paste
  [github-oidc-trust-policy.json](github-oidc-trust-policy.json) with `ACCOUNT_ID`,
  `GITHUB_OWNER`, `OWNER_ID` and `REPO_ID` filled in. Get the two IDs with:
  ```bash
  curl -s https://api.github.com/repos/GITHUB_OWNER/Risk-Runner | jq '{REPO_ID: .id, OWNER_ID: .owner.id}'
  ```
  The policy lists two subject formats because GitHub may send either
  `repo:owner/repo:ref:…` or `repo:owner@OWNER_ID/repo@REPO_ID:ref:…`. Both are exact
  matches, so only workflows on `main` of your Risk-Runner repo can assume the role. Don't
  loosen it with wildcards such as `GITHUB_OWNER*`, which would also match other accounts.
- **Permissions:** in CloudShell, run
  ```bash
  cd ~/Risk-Runner && AWS_REGION=REGION INSTANCE_ID=INSTANCE_ID GITHUB_OWNER=GITHUB_OWNER ./deploy/aws/bootstrap-permissions.sh
  ```
  It fills in the IDs itself, rewrites the trust policy (only `main` of your repo) and attaches
  three inline policies: SSM commands to this one instance
  ([deploy-role-policy.json](deploy-role-policy.json)), the database stack
  ([database/deploy-role-policy.json](database/deploy-role-policy.json)) and the serverless stack
  ([serverless/deploy-role-policy.json](serverless/deploy-role-policy.json)). Rerun it whenever
  those files change. To check what was saved:
  `aws iam get-role-policy --role-name RiskRunnerGitHubDeploy --policy-name RiskRunnerDeploySsm --query PolicyDocument`.

Copy the role ARN from the top of the role's page.

### 10. Configure the GitHub repo
These are **variables**, not secrets, because none of them is sensitive. Go to Settings → Secrets
and variables → Actions → **Variables** tab, or use `gh`:

```bash
gh variable set AWS_REGION --body REGION
gh variable set AWS_DEPLOY_ROLE_ARN --body arn:aws:iam::ACCOUNT_ID:role/RiskRunnerGitHubDeploy
gh variable set EC2_INSTANCE_ID --body INSTANCE_ID
gh variable set DOMAIN --body YOUR_DOMAIN
```

Enter plain values, with no `https://`, quotes or trailing spaces. `DOMAIN` must match the
`/risk-runner/DOMAIN` parameter. Setting `EC2_INSTANCE_ID` enables the deploy job.

## B. Deploying

- Push to `main`. **CI** runs the tests, then **Deploy to AWS** updates the database stack,
  deploys that exact commit to the server (with a health check) and deploys the serverless
  ingest stack. Each job does nothing when there's nothing to change.
- To redeploy without a code change, go to Actions → Deploy to AWS → **Run workflow** on `main`.
  The server reads Parameter Store only during a deploy, so redeploy after changing any parameter.
- The server's output appears in the "Server output" group of the *Deploy through SSM Run Command* step.
- To rotate the ingest or API token: `put` the new value, redeploy, then update every place that
  uses it (`RISK_RUNNER_TOKEN` secrets in scanned repos, the dashboard's Token button). If you
  use serverless ingestion, redeploy that stack too ([part H](#h-serverless-ingestion-lambda)),
  since the Lambda gets the token at deploy time.
- To change the database password: `put RDS_MASTER_PASSWORD "$(openssl rand -hex 24)"`, then run
  the workflow. The `database` job changes it in RDS and updates the URL; the later jobs pick it up.

Open `https://YOUR_DOMAIN`, click **Token** (top right), and paste the `RISK_RUNNER_API_TOKEN`
value. Until you do, the dashboard stays empty, because the read API requires the token.

The dashboard has three views:
- **Overview:** portfolio risk, risk bands, the 30-day trend and the top findings.
- **Findings:** every finding, with filters and search. Open a finding to see how its score
  breaks down, or triage it (accepted, false positive, fixed).
- **Repository page** (click a repository): set its business context (criticality, exposure,
  data sensitivity, compliance, revenue impact) and save to rescore. **Run analysis** needs the
  optional Claude parameters from step 5. Without them it reports "AI analysis is disabled".

## C. Connecting repositories to scan

Do this in each repository whose scan results should appear in Risk Runner.

### 1. Add two repository secrets
In the scanned repository, go to Settings → Secrets and variables → Actions → **Secrets** tab
(not Variables; the workflows read `secrets.…`):

| Secret | Value |
|---|---|
| `RISK_RUNNER_URL` | `https://YOUR_DOMAIN` |
| `RISK_RUNNER_TOKEN` | the **ingest** token: `/risk-runner/RISK_RUNNER_INGEST_TOKEN` |

Use the ingest token here, not the API token. Paste only the 64 hex characters, with no quotes,
spaces or line breaks, and copy it from the region your server uses.

With [serverless ingestion](#h-serverless-ingestion-lambda), also add `RISK_RUNNER_INGEST_URL`
(the stack's ingest URL) and pass it to the upload step as `ingest-url`. The token stays the same.

### 2. Make the workflow produce a report and upload it
Having the secrets isn't enough. Each scan job needs to:

1. **Write a report file** in a supported format (SARIF, Trivy JSON, Grype JSON or ZAP JSON).
   Console output alone is not uploaded.
2. **Run the upload step after the scanner:**
   ```yaml
   - name: Upload to Risk Runner
     if: always()        # still upload when the scanner fails the job on findings
     uses: GITHUB_OWNER/Risk-Runner/action@main
     with:
       server-url: ${{ secrets.RISK_RUNNER_URL }}
       token: ${{ secrets.RISK_RUNNER_TOKEN }}
       report: semgrep.sarif
       fail-on-error: "true"   # optional: make a rejected upload fail the step
   ```
3. **Keep any "fail the build" behavior from blocking the upload.** Scanners set to fail on
   findings (`semgrep --error`, Trivy `exit-code: '1'`) stop later steps. Either give the upload
   `if: always()`, or generate the report in a separate non-failing step before the gating scan.
4. **Run on a normal runner with bash, curl and python3.** The upload action uses them, and
   minimal scanner containers such as `semgrep/semgrep` may not include them. Install the
   scanner instead, e.g. `pip install semgrep`.

By default a failed upload only shows a **warning** and the step stays green. Check the step
log, or set `fail-on-error: "true"` while setting things up.

Only scans of the repository's **default branch** create, reopen or fix findings. Scans of
other branches and pull requests are recorded but don't change posture.

#### Example: Semgrep (SAST) that still fails the build on findings

```yaml
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install semgrep
      - run: semgrep scan --config p/default --sarif --output semgrep.sarif --metrics off --error
      - name: Upload to Risk Runner
        if: always()
        uses: GITHUB_OWNER/Risk-Runner/action@main
        with:
          server-url: ${{ secrets.RISK_RUNNER_URL }}
          token: ${{ secrets.RISK_RUNNER_TOKEN }}
          report: semgrep.sarif
          scan-type: sast
```

#### Example: Trivy image scan (SCA), with all severities sent and HIGH/CRITICAL still failing the build

```yaml
      - run: docker build -t app-image .
      - name: Trivy report for Risk Runner
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          image-ref: app-image
          format: json
          output: trivy.json
          exit-code: "0"
      - name: Upload to Risk Runner
        uses: GITHUB_OWNER/Risk-Runner/action@main
        with:
          server-url: ${{ secrets.RISK_RUNNER_URL }}
          token: ${{ secrets.RISK_RUNNER_TOKEN }}
          report: trivy.json
      - name: Fail on HIGH/CRITICAL
        uses: aquasecurity/trivy-action@v0.36.0
        with:
          image-ref: app-image
          severity: HIGH,CRITICAL
          ignore-unfixed: true
          exit-code: "1"
```

For a job with several images, give each report a different file name. Pin scanner actions to a
version tag rather than `@master`.

More complete workflows: [examples/security-scan.yml](../../examples/security-scan.yml)
(CodeQL, Trivy, ZAP) and [examples/juice-shop-security-scan.yml](../../examples/juice-shop-security-scan.yml).

### 3. Check the upload
Push to the default branch and open the run. A successful upload step logs a line like:

```
Risk Runner: semgrep (sast): 42 findings, 42 new, 0 fixed. Repository risk score: 71.3
```

The repository then appears in the dashboard. CVE, EPSS and KEV enrichment follows within a few
minutes. If the log shows a warning instead, see [F. Troubleshooting](#f-troubleshooting).

## D. Field test with OWASP Juice Shop

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
3. Add the two secrets from [section C](#1-add-two-repository-secrets) to the fork:
   ```bash
   gh secret set RISK_RUNNER_URL --repo GITHUB_OWNER/juice-shop
   gh secret set RISK_RUNNER_TOKEN --repo GITHUB_OWNER/juice-shop
   ```
4. Commit and push to `master`. Semgrep (SAST), Trivy (SCA) and ZAP baseline (DAST) run and upload.

## E. What to check

1. **Findings:** the scanned repository appears with findings from each scanner. Wait a minute or two for CVE/EPSS/KEV enrichment.
2. **Business context:** set criticality 5, internet-facing, restricted data, "PCI", revenue-impacting, then save. Scores should rise.
3. **Ranking:** do Juice Shop's known SQL injection, XSS and auth problems rank near the top? If not, tune the weights in `scoring.py`.
4. **Claude analysis (optional):** add the AI parameters (step 5), redeploy, then click **Run analysis**.
5. **Fixed findings:** remove a vulnerable dependency and push. Those findings should be marked fixed.

## F. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Session Manager: *"DHMC is not enabled and IAM instance profile is not attached"*; agent log: *"unable to acquire credentials … instance management role is not configured"* | The instance has no role. EC2 → instance → Actions → Security → **Modify IAM role** → pick the step 2 role → reboot → wait 2–5 min. Ignore the DHMC suggestion. |
| The role isn't offered in *Modify IAM role* | It wasn't created as *AWS service → EC2*. Its trust relationship must show `ec2.amazonaws.com`. Recreate it. |
| Session Manager still can't connect with the role attached | Confirm the role has `AmazonSSMManagedInstanceCore`, check Systems Manager → Fleet Manager for the instance, and check that the subnet has an internet route and the security group allows outbound traffic. |
| `git clone` asks for a password | The URL is malformed (often two commands pasted together) or the repo is private. Ctrl+C, then see step 6. |
| `deploy.sh`: *"Missing parameter /risk-runner/DOMAIN"* (or another name) | The parameters are in a different region, or that one wasn't saved. On the instance: `aws ssm get-parameters-by-path --region REGION --path /risk-runner --query 'Parameters[].Name'`. An empty list means a region mismatch: recreate the parameters in the right region and delete the others. |
| `deploy.sh`: AccessDenied reading parameters | The instance role's inline policy has the wrong region or account ID, or a placeholder left in it. |
| `deploy.sh`: *"Missing parameter /risk-runner/RISK_RUNNER_DATABASE_URL"* | The database hasn't been created in this region yet. Run step 5a, or the workflow's `database` job. |
| `database` job: *"risk-runner already exists"* | A database with that name was created outside the stack (for example in the console). Delete or rename it, or import it into the stack, then rerun. |
| `database` job: AccessDenied | The deploy role is missing the database policy. Rerun `bootstrap-permissions.sh`. |
| App unhealthy; its log (`docker compose -f docker-compose.aws.yml logs risk-runner --tail 80`) shows *"connection timed out"* to the RDS host | The database allows the instance's **first** security group. If you changed the instance's security groups, rerun the workflow so the stack picks up the new one. |
| App log: *"password authentication failed"* | The URL and the RDS password don't match, usually after a change in the RDS console. Rerun the workflow: the `database` job sets both from `RDS_MASTER_PASSWORD`. |
| Deploy workflow: *"Could not assume role with OIDC: Not authorized to perform sts:AssumeRoleWithWebIdentity"* | The trust policy doesn't match what GitHub sent. In the deploy region, open CloudTrail → Event history → Event name `AssumeRoleWithWebIdentity`. The event's `userIdentity.userName` is the exact `sub` GitHub sent; make the trust policy match it. Also check the provider ARN, the audience and the `AWS_DEPLOY_ROLE_ARN` variable. |
| Deploy workflow: *"not authorized to perform: ssm:SendCommand … because no identity-based policy allows"* | The deploy role's inline policy still says `INSTANCE_ID` (or has the wrong region or account). Fill it in and save. |
| Health check: *"TLS connect error … tlsv1 alert internal error"* | Caddy has no certificate yet. On the instance, run `docker compose -f docker-compose.aws.yml logs caddy --tail 100`. A *"Timeout during connect"* for a different hostname or IP means `/risk-runner/DOMAIN` is wrong: fix it and redeploy. A timeout for your own IP means ports 80/443 are blocked. *rateLimited* means a Let's Encrypt limit: switch to `….nip.io` (update the parameter and the variable, then redeploy). If the log shows the certificate is still being obtained, wait and rerun. |
| `nslookup` on an sslip.io name: *"Non-existent domain"* | Your local DNS is blocking it. Test with `nslookup <name> 8.8.8.8`. |
| Upload warning: *"Invalid or missing bearer token"* | `RISK_RUNNER_TOKEN` isn't the server's current ingest token. Common causes: the API token was used, the value came from old parameters or another region, or extra quotes or whitespace were pasted. Re-copy it and rerun the scan. |
| Upload warning: *"report not found"* | The scanner didn't write the file named in `report:`. Check the scanner's output flags and that both steps run in the same job. |
| Scans run but nothing appears in the dashboard | Check the upload step's log for warnings (uploads stay green by default), check that the push went to the default branch, and check that the dashboard Token is set. |
| *"AI analysis is disabled"* | Optional feature: add `RISK_RUNNER_AI_ENABLED=true` and `ANTHROPIC_API_KEY` parameters (step 5), then redeploy. |

## G. Pausing, tearing down and rebuilding

Rough monthly costs (us-east-1 list prices):

| Item | Per month |
|---|---|
| EC2 t3.small, running | ~$15 |
| EC2 20 GB disk | ~$1.60 |
| Public IPv4 address (billed even while the instance is stopped) | ~$3.60 |
| RDS db.t4g.micro, Single-AZ, running (free tier covers it on eligible accounts) | ~$11.70 |
| RDS 20 GB storage and backups | ~$2.30 |
| Serverless ingestion (Lambda, SQS, S3, API), at about 1,000 uploads | under $1 |

Parameters, IAM roles, the OIDC provider and the S3 gateway endpoint are free. Without the
Postgres container, a smaller instance (t3.micro, ~$7.60) may be enough. The frontend build on a
1 GB instance can run out of memory, so add swap if you try it.

### Pause (keeps all data and settings)

1. GitHub → Risk-Runner → Actions → **Deploy to AWS** → **⋯** → **Disable workflow**, so pushes
   to `main` don't try to deploy to a stopped instance. (CI still runs.)
2. Optionally disable the scan workflows in scanned repositories. Otherwise their uploads warn,
   or fail if `fail-on-error` is set.
3. EC2 → the instance → Instance state → **Stop**. Don't terminate it.
4. RDS → the database → Actions → **Stop temporarily**. RDS starts it again after 7 days, so
   repeat this weekly or take a snapshot and delete it for longer pauses.

While paused, you pay only for the EC2 disk, the Elastic IP and the RDS storage, about $7 a month.

**Resume:**
1. RDS → the database → Actions → **Start**, and wait until it's *Available*. Then EC2 →
   Instance state → **Start**. The Elastic IP, hostname, certificate and data are all kept, and
   the containers restart on their own.
2. After a minute or two, check `https://YOUR_DOMAIN/api/health`.
3. Re-enable the **Deploy to AWS** workflow and run it once, which deploys any commits pushed
   while paused. Re-enable any scan workflows you disabled.

### Tear down but keep the setup reusable (about $0 a month)

This deletes the server and the database: findings, triage decisions and business context.
Findings come back on the next scans; triage decisions and business context must be re-entered.

1. Disable the **Deploy to AWS** workflow (or unset `EC2_INSTANCE_ID` so the deploy job skips).
2. If you use serverless ingestion: CloudFormation → `risk-runner-ingest` → **Delete**. Empty its
   reports bucket first if the delete stops on it.
3. EC2 → the instance → Instance state → **Terminate**.
4. EC2 → Elastic IPs → select it → Actions → **Release Elastic IP addresses**.
5. RDS → the database → Modify → turn off deletion protection → Apply immediately. Then
   CloudFormation → `risk-runner-db` → **Delete**. A final snapshot is taken automatically (about
   $0.095 per GB-month; delete it under RDS → Snapshots when you no longer need it).
6. Keep the parameters, both IAM roles and the OIDC provider. They cost nothing and make
   rebuilding quick.

**Rebuild later:**
1. Step 3: launch a new instance with the same instance role, and allocate and associate a new Elastic IP.
2. The IP is new, so update the hostname. With your own domain, point the A record at the new
   IP. With sslip.io or nip.io, the hostname changes: update the `/risk-runner/DOMAIN` parameter
   and the `DOMAIN` variable, and `RISK_RUNNER_URL` in scanned repositories.
3. Step 5a: create the database again. To get the old data back, restore the final snapshot
   into it afterwards (RDS → Snapshots → Restore creates a separate database; copy the data over
   with `pg_dump`/`pg_restore` as in `deploy/aws/migrate-to-rds.sh`).
4. Update the `EC2_INSTANCE_ID` variable and rerun `bootstrap-permissions.sh` with the new `INSTANCE_ID`.
5. Steps 6–7: clone and deploy by hand. Redeploy the serverless stack if you use it.
6. Re-enable the **Deploy to AWS** workflow. The tokens are unchanged, so the scanned
   repositories' `RISK_RUNNER_TOKEN` and your dashboard Token still work.

### Remove everything

Tear down as above, then:
- Delete the parameters:
  ```bash
  aws ssm delete-parameters --region REGION --names $(aws ssm get-parameters-by-path --region REGION --path /risk-runner --query 'Parameters[].Name' --output text)
  ```
- Delete the `risk-runner-artifacts-ACCOUNT_ID-REGION` S3 bucket (serverless deploy packages).
- Delete both IAM roles and, if nothing else uses it, the `token.actions.githubusercontent.com` identity provider.
- Delete the `AWS_REGION`, `AWS_DEPLOY_ROLE_ARN`, `EC2_INSTANCE_ID`, `DOMAIN` and `SERVERLESS_INGEST` variables.
- Remove the `RISK_RUNNER_URL`, `RISK_RUNNER_INGEST_URL` and `RISK_RUNNER_TOKEN` secrets and the upload steps from scanned repositories.

## H. Serverless ingestion (Lambda)

Optional. Reports go from GitHub Actions to S3 and are processed by Lambda, so uploads don't
depend on the web server and large reports (up to 50 MB) never pass through it.

```
Action ─POST /uploads─▶ API Lambda ─▶ presigned S3 upload        (no VPC, never touches the DB)
Action ─report─▶ S3 reports/ ─▶ SQS ─▶ processor Lambda ─▶ RDS    (in the VPC, no internet)
Action ─GET /uploads/{id}─▶ API Lambda ─▶ result (score, counts)  (polls up to 2 minutes)
```

- The stack is [serverless/template.yaml](serverless/template.yaml): an S3 bucket (private,
  encrypted, files kept 90 days), an SQS queue with a dead-letter queue (3 attempts), two Lambda
  functions, an HTTP API, an S3 gateway endpoint (free) and a security group rule that lets the
  processor reach RDS.
- The processor has no internet access, so it doesn't fetch CVE intel. The web server checks
  every 10 minutes for CVEs without intel (`RISK_RUNNER_PENDING_ENRICHMENT_MINUTES`) and
  enriches them. No NAT gateway (about $33 a month) is needed.
- At most two reports are processed at once. Reports for the same repository wait for each
  other (a database lock), so lifecycle changes don't conflict.
- The web server's `POST /api/v1/ingest` keeps working, and you can ingest while the dashboard is
  in use. Uploads to either one share the same lock, so a web upload and a Lambda upload for one
  repository also take turns. Repos can move over one at a time.

Requires the RDS database from step 5a, named `risk-runner`.

### 1. Deploy it
The **Deploy to AWS** workflow deploys the stack on every run (the `deploy-ingest` job). Its
summary page shows the ingest URL and the `gh secret set` command for step 3. To skip it, set
`gh variable set SERVERLESS_INGEST --body false`.

The script reads `RISK_RUNNER_DATABASE_URL` and `RISK_RUNNER_INGEST_TOKEN` from Parameter Store,
finds the VPC, subnets and security group from the RDS instance, builds the Lambda package and
deploys the `risk-runner-ingest` stack. The first deploy takes about 5 minutes. If you change the
ingest token or the database URL, run the workflow again: the functions get both values at
deploy time.

### 2. Deploying it by hand (optional)
From CloudShell, with the repo cloned as in step 5a:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh && source ~/.local/bin/env
```

```bash
cd ~/Risk-Runner && git pull && AWS_REGION=REGION ./deploy/aws/serverless/deploy.sh
```

It ends with `Deployed. Ingest URL: https://abc123.execute-api.REGION.amazonaws.com`.

### 3. Point scanned repositories at it
In each scanned repository, add the secret and the `ingest-url` input:

```bash
gh secret set RISK_RUNNER_INGEST_URL --repo OWNER/REPO --body https://abc123.execute-api.REGION.amazonaws.com
```

```yaml
- name: Upload to Risk Runner
  if: always()
  uses: GITHUB_OWNER/Risk-Runner/action@main
  with:
    ingest-url: ${{ secrets.RISK_RUNNER_INGEST_URL }}
    token: ${{ secrets.RISK_RUNNER_TOKEN }}
    report: trivy.json
```

When `ingest-url` is set, `server-url` isn't needed. The step log looks the same as before. If
processing takes longer than `wait-seconds` (default 120), the step reports the upload as queued
and the results appear on the dashboard when they're done.

### 4. Check it
- The upload step logs `Risk Runner: … Repository risk score: …` and the dashboard shows the scan.
- Logs: CloudWatch → Log groups → `/aws/lambda/risk-runner-ingest-api` and `…-processor`.
- Failed messages: SQS → `risk-runner-ingest-dlq` → Send and receive messages → Poll. It should be empty.

### Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `deploy.sh`: *"Missing parameter /risk-runner/…"* | Run step 5b for that parameter, in this region. |
| `deploy.sh`: *"DBInstanceNotFound"* | The database isn't named `risk-runner`, or it's in another region. Set `DB_INSTANCE_ID=<name>` before the command. |
| `deploy.sh`: *"uv: command not found"* | Run the uv install line, or `source ~/.local/bin/env` in a new CloudShell session. |
| Stack fails on `S3GatewayEndpoint`: *"route table … already has a route with destination-prefix-list-id"* | The VPC already has an S3 gateway endpoint for some route tables. Add those route tables to it instead (VPC → Endpoints), then rerun. |
| Upload warning: *"ingest endpoint rejected the upload: {"detail":"Invalid or missing bearer token"}"* | `RISK_RUNNER_TOKEN` doesn't match the token the stack was deployed with. If you rotated it, rerun `deploy.sh`. |
| Upload stays *queued*; processor log shows a timeout connecting to RDS | The processor's security group rule is missing. Rerun `deploy.sh`. If the database has several security groups, check that the first one listed in RDS is attached to it. |
| Upload stays *queued*; processor log is empty | Check the queue (messages in flight or in the DLQ) and that the bucket's event notification points at the queue (S3 → bucket → Properties → Event notifications). |
| Upload warning: *"report was rejected: …"* | The report isn't a supported format. Same causes as a 422 from the web server. |
| CVEs show no EPSS/KEV for a while | Expected for up to 10 minutes after a Lambda ingest. Check the web server's log for *"Enriching N new CVEs"*. |

## I. Moving an existing deployment to RDS and Lambda

For a server set up with the older guide (Postgres in a container on the instance). The workflow
does the move: it creates the database, copies the data, deploys the new server and the
serverless stack. The old database volume stays on the instance, untouched, so you can roll back.

### 1. Allow the workflow to do it (once, in CloudShell)
The role from step 9 can only send commands to the instance. Give it the new permissions and
let it deploy from the branch you're trying. Leave `BRANCH=…` out once the change is merged.

```bash
git clone -b feat/serverless-ingest https://github.com/GITHUB_OWNER/Risk-Runner.git ~/Risk-Runner-next
```

```bash
cd ~/Risk-Runner-next && AWS_REGION=REGION INSTANCE_ID=INSTANCE_ID GITHUB_OWNER=GITHUB_OWNER BRANCH=feat/serverless-ingest ./deploy/aws/bootstrap-permissions.sh
```

It ends with `Done. Role ARN: …`. It may list the inline policy you pasted in step 9; that one is
now covered by `RiskRunnerDeploySsm` and can be deleted.

### 2. Run the workflow from the branch
GitHub → Risk-Runner → Actions → **Deploy to AWS** → **Run workflow** → Branch:
`feat/serverless-ingest` → **Run workflow**. It takes about 20 minutes the first time:

| Job | What it does | Typical time |
|---|---|---|
| `database` | Creates the RDS database and the `RDS_MASTER_PASSWORD` / `RISK_RUNNER_DATABASE_URL` parameters | ~10 min first time |
| `migrate` | On the instance: dumps the old Postgres container and restores it into RDS, then prints row counts from both. Skips if RDS already has data. | ~1 min |
| `deploy` | Checks out the branch on the instance, starts the new version (no Postgres container) and runs the health check | ~5 min |
| `deploy-ingest` | Deploys the Lambda stack. The run's **Summary** shows the ingest URL | ~5 min |

**While you're testing, don't push to `main`.** That runs `main`'s version of the workflow,
which puts the old version back on the server (the same as a rollback, below).

Check the result:
- The `migrate` job's *Server output* shows the row counts (old | RDS); they should match.
- The dashboard still shows your repositories, findings, triage decisions and business context.

### 3. Try serverless ingestion on one repository
In a scanned repository: add the `RISK_RUNNER_INGEST_URL` secret with the command from the run's
Summary, and change its upload step to

```yaml
uses: GITHUB_OWNER/Risk-Runner/action@feat/serverless-ingest   # ingest-url isn't on main yet
with:
  ingest-url: ${{ secrets.RISK_RUNNER_INGEST_URL }}
  token: ${{ secrets.RISK_RUNNER_TOKEN }}
  report: …
```

Push to its default branch and check the upload step's log and the dashboard. Repositories that
still use `server-url` keep working.

### 4. Merge
When you're happy: merge the branch (the push to `main` runs the workflow again; every job
finds nothing to change), change test repositories back to `action@main`, and rerun step 1
**without** `BRANCH=…` so only `main` can deploy.

### Doing it by hand instead
The same scripts work without the workflow, one at a time: `deploy/aws/database/deploy.sh` in
CloudShell (step 5a), then on the instance (Session Manager, `sudo -iu ubuntu`, `cd ~/Risk-Runner`):
`git fetch origin && git show origin/feat/serverless-ingest:deploy/aws/migrate-to-rds.sh | AWS_REGION=REGION bash`,
then `git checkout feat/serverless-ingest && AWS_REGION=REGION ./deploy/deploy.sh`, and part H
step 2 for the Lambda stack.

To look inside the RDS database from the instance:

```bash
PGURL=$(aws ssm get-parameter --region REGION --with-decryption --name /risk-runner/RISK_RUNNER_DATABASE_URL --query Parameter.Value --output text | sed 's/+psycopg//')
```

```bash
docker run --rm -it --network host postgres:17 psql "$PGURL"
```

Then for example `select count(*) from findings;`.

### Roll back if something is wrong
Actions → **Deploy to AWS** → **Run workflow** → Branch: `main`. (Before merging, `main` still
has the old version.) This starts the old Postgres container again on its untouched volume. Anything uploaded while
running on RDS isn't in it; rerun those scans. Change test repos back to `action@main` and
`server-url`. The RDS database and the `risk-runner-ingest` stack can stay (they cost money) or
be deleted (see part G). To try again later, just run the workflow on the branch again: the
`migrate` job skips the copy because RDS already has data, so anything uploaded to the old
database after the first copy stays there.

### Clean up once you're sure
After a week or two on RDS, on the instance:

```bash
docker volume rm risk-runner_pgdata && rm ~/risk_runner-*.dump
```

```bash
aws ssm delete-parameter --region REGION --name /risk-runner/POSTGRES_PASSWORD
```

Optionally move the instance to a smaller type (part G).
