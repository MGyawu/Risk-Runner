from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RISK_RUNNER_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./risk_runner.db"
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
    nvd_api_key: str = ""
    epss_url: str = "https://api.first.org/data/v1/epss"
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # AI (Claude). Uses the standard Anthropic credential chain (ANTHROPIC_API_KEY, etc).
    ai_enabled: bool = False
    ai_model: str = "claude-opus-5-5"
    ai_effort: str = "medium"
    ai_max_findings_per_repo: int = 40

    cors_origins: list[str] = ["http://localhost:5173"]


settings = Settings()
