from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RISK_RUNNER_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./risk_runner.db"
    # "queue" (default connection pool) or "none" (one connection per session; used on Lambda,
    # where a pool outlives the request and holds idle connections open on RDS).
    db_pool: str = "queue"
    host: str = "0.0.0.0"
    port: int = 8000

    # Bearer token required by the ingest endpoint (GitHub Actions uploads).
    # Leave empty only for local development.
    ingest_token: str = ""
    # Optional token required for the dashboard/read API.
    api_token: str = ""

    # Threat intel
    enrichment_enabled: bool = True
    enrichment_interval_hours: float = 12.0
    # Reports ingested by the serverless pipeline (Lambda has no internet access) don't trigger
    # enrichment. The web server checks this often for CVEs that have no intel yet.
    pending_enrichment_minutes: float = 10.0
    nvd_api_key: str = ""
    epss_url: str = "https://api.first.org/data/v1/epss"
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # AI (Claude). Uses the standard Anthropic credential chain (ANTHROPIC_API_KEY, etc).
    ai_enabled: bool = False
    ai_model: str = "claude-opus-5-5"
    ai_effort: str = "medium"
    ai_max_findings_per_repo: int = 40

    # Serverless ingestion (Lambda): S3 bucket holding uploaded reports, upload metadata and results.
    reports_bucket: str = ""

    cors_origins: list[str] = ["http://localhost:5173"]


settings = Settings()
