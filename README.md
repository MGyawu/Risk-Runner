# Risk Runner

Business-aware Application Security Posture Management (ASPM). Risk Runner ingests SAST, SCA and DAST results from GitHub Actions, enriches them with live threat intelligence (NVD CVSS, FIRST EPSS, CISA KEV), weighs them against each repository's business context, and uses Claude to refine scores and draft remediation plans. The result is a dashboard of **business-sensitive risk scores** for your work repositories.

```
GitHub Actions ──(SARIF / Trivy / Grype / ZAP)──▶ /api/v1/ingest
                                                    │ parse · dedupe · lifecycle
                                                    ▼
             NVD · EPSS · KEV ──▶ enrichment ──▶ scoring ◀── business context
                                                    │
                                          Claude (bounded ±15 adjustment,
                                          rationale, remediation summary)
                                                    ▼
                                             React dashboard
```

## Quick start

```bash
cd backend && uv sync && uv run risk-runner        # API on :8000
cd frontend && npm install && npm run dev           # dashboard on :5173 (proxies /api)
```

Or build the frontend once (`npm run build`) and the backend serves it at `http://localhost:8000`.

Docker (with Postgres): `cp .env.example .env`, edit it, then `docker compose up --build`.

Single-server deployment with HTTPS (e.g. AWS EC2): set `DOMAIN` and `POSTGRES_PASSWORD` in `.env`, then `docker compose -f docker-compose.aws.yml up -d --build`. Caddy obtains a Let's Encrypt certificate automatically. For automated deploys to AWS on every push to `main` (GitHub OIDC, SSM, Parameter Store), follow [deploy/aws/README.md](deploy/aws/README.md). A field-test workflow that scans OWASP Juice Shop is in [examples/juice-shop-security-scan.yml](examples/juice-shop-security-scan.yml).

Send a report by hand:

```bash
curl -H "Authorization: Bearer $RISK_RUNNER_INGEST_TOKEN" \
  -F report=@trivy.json -F repository=acme/payments-api -F branch=main \
  http://localhost:8000/api/v1/ingest
```

## GitHub Actions

Add the upload step after any scanner. See [.github/workflows/example-security-scan.yml](.github/workflows/example-security-scan.yml) for CodeQL + Trivy + ZAP.

```yaml
- uses: YOUR-ORG/Risk-Runner/action@main
  with:
    server-url: ${{ secrets.RISK_RUNNER_URL }}
    token: ${{ secrets.RISK_RUNNER_TOKEN }}
    report: trivy.json          # format and scan type are auto-detected
```

| Format | Typical tools | Default type |
|---|---|---|
| SARIF 2.1.0 | CodeQL, Semgrep, Bandit, Snyk Code, Checkmarx | `sast` (override with `scan-type`) |
| Trivy JSON | `trivy fs/image --format json` | `sca` |
| Grype JSON | `grype -o json` | `sca` |
| ZAP JSON | `zap-baseline.py -J report.json` | `dast` |

**Lifecycle.** Posture tracks the default branch. A default-branch scan opens new findings, reopens regressions, and marks findings that disappeared as fixed (per tool and scan type). Scans of other branches are recorded but don't change findings. Findings that are triaged as *accepted* or *false positive* stay that way.

## Scoring

Every score can be explained, and the dashboard shows each factor for every finding.

```
risk       = clamp(base + ai_adjustment, 0, 100)
base       = 100 · raw / (raw + 0.5)
raw        = technical × likelihood × business
technical  = CVSS / 10, or tool severity mapped to CVSS-like values
likelihood = 1.6 if in CISA KEV
             else 0.6 + 0.9 · min(1, EPSS / 0.3)
             else by type: DAST 1.1, SAST 0.9, SCA 0.8
business   = criticality(1–5: 0.6–1.4) × exposure(internal .85, partner 1.05, internet 1.25)
             × data sensitivity(public .85 … restricted 1.3) × compliance(+5% each, max 15%)
             × revenue impacting(1.1)
```

Repository score = `100 · (1 − Π(1 − (sᵢ/100)³))`. A few severe findings dominate, while many low findings add up slowly. Suggested SLAs: ≥85 → 7 days, ≥65 → 30, ≥40 → 90, otherwise 180.

Threat intel refreshes after each ingest that references CVEs, and every `RISK_RUNNER_ENRICHMENT_INTERVAL_HOURS` hours (default 12). It can also be triggered from the dashboard. NVD is rate limited, so set `RISK_RUNNER_NVD_API_KEY` for faster CVSS backfill.

## AI analysis

Set `RISK_RUNNER_AI_ENABLED=true` and Anthropic credentials (`ANTHROPIC_API_KEY`). Then click **Run analysis** on a repository page, or call `POST /api/v1/repos/{id}/analyze`. Claude (`claude-opus-5-5` by default) reviews the top open findings against the business context. It returns a per-finding adjustment, clamped to ±15 points, with a rationale, plus a prioritized remediation summary. Scanner text is passed as data, and the bounded adjustment limits what a prompt injection hidden in code or scanner output could do. Requests use structured JSON output and server-side refusal fallbacks. Analysis is on-demand to keep costs predictable.

## Configuration

All settings are environment variables prefixed `RISK_RUNNER_` (see [.env.example](.env.example) and [config.py](backend/src/risk_runner/config.py)).

| Variable | Purpose |
|---|---|
| `INGEST_TOKEN` | Bearer token required by `/api/v1/ingest`. **Set this in any shared deployment.** |
| `API_TOKEN` | Optional bearer token for the dashboard/read API (enter it via **Token** in the UI). |
| `DATABASE_URL` | SQLAlchemy URL. Defaults to SQLite; use `postgresql+psycopg://…` in production. |
| `AI_ENABLED`, `AI_MODEL`, `AI_EFFORT` | Claude analysis settings. |
| `NVD_API_KEY`, `ENRICHMENT_INTERVAL_HOURS` | Threat intel settings. |

## API

| Method | Path | |
|---|---|---|
| POST | `/api/v1/ingest` | Upload a report (multipart: `report`, `repository`, optional `scan_type`, `format`, `tool`, `branch`, `commit_sha`, `workflow_run_url`) |
| GET | `/api/v1/overview` | Portfolio stats, risk bands, 30-day trend, top findings |
| GET | `/api/v1/repos` · `/repos/{id}` · `/repos/{id}/scans` | Repositories |
| PATCH | `/api/v1/repos/{id}` | Update business context (rescores the repository) |
| POST | `/api/v1/repos/{id}/analyze` | Run AI analysis |
| GET | `/api/v1/findings` | Filters: `repo_id`, `status` (or `all`), `scan_type`, `kev`, `min_score`, `q` |
| PATCH | `/api/v1/findings/{id}` | Triage: `open`, `accepted`, `false_positive`, `fixed` |
| POST | `/api/v1/intel/refresh` | Refresh EPSS/KEV/NVD and rescore everything |

Interactive docs: `http://localhost:8000/docs`.

## Development

```bash
cd backend && uv run pytest        # parsers, scoring, lifecycle, API, mocked AI
cd frontend && npm run build       # type-check + bundle
```

## Roadmap ideas

- SSO / per-user auth and audit log for triage decisions
- Database migrations (Alembic) before the schema changes
- More formats: CycloneDX VEX, Snyk JSON, npm/pip audit, Nuclei
- Import business context from a service catalog (Backstage) or GitHub custom properties
- Reachability signals for SCA and dedupe across tools (same CVE from Trivy and Grype)
- Jira/GitHub Issues sync and Slack alerts for new KEV findings
