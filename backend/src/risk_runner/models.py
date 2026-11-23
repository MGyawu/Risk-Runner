from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class ScanType(StrEnum):
    SAST = "sast"
    SCA = "sca"
    DAST = "dast"


class Exposure(StrEnum):
    INTERNAL = "internal"  # only reachable on the corporate network
    PARTNER = "partner"  # exposed to authenticated partners / B2B
    INTERNET = "internet"  # public internet


class DataSensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"  # PII, PHI, PCI, secrets


class FindingStatus(StrEnum):
    OPEN = "open"
    FIXED = "fixed"
    ACCEPTED = "accepted"  # risk accepted
    FALSE_POSITIVE = "false_positive"


class Repository(Base):
    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(primary_key=True)
    full_name: Mapped[str] = mapped_column(String(255), unique=True, index=True)  # owner/repo
    default_branch: Mapped[str] = mapped_column(String(255), default="main")

    # Business context
    business_unit: Mapped[str | None] = mapped_column(String(255))
    owner: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    criticality: Mapped[int] = mapped_column(Integer, default=3)  # 1 (low) .. 5 (crown jewel)
    exposure: Mapped[str] = mapped_column(String(32), default=Exposure.INTERNAL)
    data_sensitivity: Mapped[str] = mapped_column(String(32), default=DataSensitivity.INTERNAL)
    compliance: Mapped[list[str]] = mapped_column(JSON, default=list)  # e.g. ["PCI", "SOC2"]
    revenue_impacting: Mapped[bool] = mapped_column(Boolean, default=False)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    ai_summary: Mapped[str | None] = mapped_column(Text)
    ai_summary_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    findings: Mapped[list["Finding"]] = relationship(back_populates="repository", cascade="all, delete-orphan")
    scans: Mapped[list["Scan"]] = relationship(back_populates="repository", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True)
    scan_type: Mapped[str] = mapped_column(String(16))
    tool: Mapped[str] = mapped_column(String(128))
    format: Mapped[str] = mapped_column(String(32))
    branch: Mapped[str | None] = mapped_column(String(255))
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    workflow_run_url: Mapped[str | None] = mapped_column(String(1024))
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    new_count: Mapped[int] = mapped_column(Integer, default=0)
    fixed_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    repository: Mapped[Repository] = relationship(back_populates="scans")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("repository_id", "fingerprint"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    repository_id: Mapped[int] = mapped_column(ForeignKey("repositories.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    scan_type: Mapped[str] = mapped_column(String(16), index=True)
    tool: Mapped[str] = mapped_column(String(128))
    rule_id: Mapped[str | None] = mapped_column(String(512))
    title: Mapped[str] = mapped_column(String(1024))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))  # critical/high/medium/low/info (tool-reported)
    cwe: Mapped[list[str]] = mapped_column(JSON, default=list)
    cve: Mapped[str | None] = mapped_column(String(32), index=True)

    # Location
    file_path: Mapped[str | None] = mapped_column(String(1024))
    line: Mapped[int | None] = mapped_column(Integer)
    url: Mapped[str | None] = mapped_column(String(2048))  # DAST endpoint
    package: Mapped[str | None] = mapped_column(String(512))
    installed_version: Mapped[str | None] = mapped_column(String(128))
    fixed_version: Mapped[str | None] = mapped_column(String(256))

    # Threat intel (copied from CveIntel at scoring time)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)

    # Scoring
    base_score: Mapped[float] = mapped_column(Float, default=0.0)  # deterministic 0-100
    ai_adjustment: Mapped[float] = mapped_column(Float, default=0.0)  # bounded +/- points
    ai_rationale: Mapped[str | None] = mapped_column(Text)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)  # final 0-100
    score_factors: Mapped[dict] = mapped_column(JSON, default=dict)

    status: Mapped[str] = mapped_column(String(32), default=FindingStatus.OPEN, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    fixed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    repository: Mapped[Repository] = relationship(back_populates="findings")


class CveIntel(Base):
    """Cache of CVE threat intelligence (NVD CVSS, FIRST EPSS, CISA KEV)."""

    __tablename__ = "cve_intel"

    cve: Mapped[str] = mapped_column(String(32), primary_key=True)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(256))
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    kev_due_date: Mapped[str | None] = mapped_column(String(32))
    kev_ransomware: Mapped[bool] = mapped_column(Boolean, default=False)
    nvd_fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
