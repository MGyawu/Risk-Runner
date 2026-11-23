from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from .models import DataSensitivity, Exposure, FindingStatus


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class RepoContextUpdate(BaseModel):
    default_branch: str | None = None
    business_unit: str | None = None
    owner: str | None = None
    description: str | None = None
    criticality: int | None = Field(default=None, ge=1, le=5)
    exposure: Exposure | None = None
    data_sensitivity: DataSensitivity | None = None
    compliance: list[str] | None = None
    revenue_impacting: bool | None = None


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class RepoOut(ORM):
    id: int
    full_name: str
    default_branch: str
    business_unit: str | None
    owner: str | None
    description: str | None
    criticality: int
    exposure: str
    data_sensitivity: str
    compliance: list[str]
    revenue_impacting: bool
    risk_score: float
    ai_summary: str | None
    ai_summary_at: datetime | None
    updated_at: datetime


class RepoSummary(RepoOut):
    open_findings: int = 0
    kev_findings: int = 0
    by_type: dict[str, int] = {}
    by_band: SeverityCounts = SeverityCounts()
    last_scan_at: datetime | None = None


class FindingOut(ORM):
    id: int
    repository_id: int
    repository_name: str | None = None
    scan_type: str
    tool: str
    rule_id: str | None
    title: str
    description: str | None
    severity: str
    cwe: list[str]
    cve: str | None
    file_path: str | None
    line: int | None
    url: str | None
    package: str | None
    installed_version: str | None
    fixed_version: str | None
    cvss_score: float | None
    epss_score: float | None
    epss_percentile: float | None
    in_kev: bool
    base_score: float
    ai_adjustment: float
    ai_rationale: str | None
    risk_score: float
    score_factors: dict
    status: str
    first_seen: datetime
    last_seen: datetime
    fixed_at: datetime | None
    sla_days: int | None = None


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


class ScanOut(ORM):
    id: int
    scan_type: str
    tool: str
    format: str
    branch: str | None
    commit_sha: str | None
    workflow_run_url: str | None
    finding_count: int
    new_count: int
    fixed_count: int
    created_at: datetime


class IngestResult(BaseModel):
    scan: ScanOut
    repository: str
    repository_risk_score: float
    cves: int


class Overview(BaseModel):
    repositories: int
    open_findings: int
    kev_findings: int
    portfolio_risk: float
    by_band: SeverityCounts
    by_type: dict[str, int]
    top_findings: list[FindingOut]
    trend: list[dict]
