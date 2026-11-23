"""Deterministic, explainable, business-aware risk scoring.

final_risk = clamp(base_score + ai_adjustment, 0, 100)

base_score = 100 * raw / (raw + K)            (saturating curve, K = 0.5)
raw        = technical * likelihood * business

technical  : CVSS/10, or tool severity mapped to a CVSS-like value
likelihood : CISA KEV  -> 1.6
             EPSS      -> 0.6 + 0.9 * min(1, epss / 0.3)   (EPSS >= 30% treated as near-certain)
             no CVE    -> by scan type (DAST 1.1 runtime-confirmed, SAST 0.9, SCA 0.8)
business   : criticality x exposure x data sensitivity x compliance x revenue
"""

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import CveIntel, Finding, FindingStatus, Repository

K = 0.5
SEVERITY_CVSS = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
CRITICALITY = {1: 0.6, 2: 0.8, 3: 1.0, 4: 1.2, 5: 1.4}
EXPOSURE = {"internal": 0.85, "partner": 1.05, "internet": 1.25}
SENSITIVITY = {"public": 0.85, "internal": 1.0, "confidential": 1.15, "restricted": 1.3}
NO_CVE_LIKELIHOOD = {"dast": 1.1, "sast": 0.9, "sca": 0.8}
ACTIVE = (FindingStatus.OPEN,)


def business_multiplier(repo: Repository) -> tuple[float, dict]:
    crit = CRITICALITY.get(repo.criticality, 1.0)
    exp = EXPOSURE.get(repo.exposure, 1.0)
    sens = SENSITIVITY.get(repo.data_sensitivity, 1.0)
    comp = 1.0 + min(0.15, 0.05 * len(repo.compliance or []))
    rev = 1.1 if repo.revenue_impacting else 1.0
    total = crit * exp * sens * comp * rev
    return total, {
        "criticality": crit,
        "exposure": exp,
        "data_sensitivity": sens,
        "compliance": round(comp, 2),
        "revenue": rev,
        "business": round(total, 3),
    }


def likelihood(f: Finding) -> tuple[float, str]:
    if f.in_kev:
        return 1.6, "kev"
    if f.epss_score is not None:
        return 0.6 + 0.9 * min(1.0, f.epss_score / 0.3), "epss"
    return NO_CVE_LIKELIHOOD.get(f.scan_type, 0.9), "scan_type"


def score_finding(f: Finding, repo: Repository, biz: float | None = None, biz_factors: dict | None = None) -> None:
    if biz is None:
        biz, biz_factors = business_multiplier(repo)
    tech = (f.cvss_score if f.cvss_score is not None else SEVERITY_CVSS.get(f.severity, 5.0)) / 10.0
    lik, lik_source = likelihood(f)
    raw = tech * lik * biz
    f.base_score = round(100 * raw / (raw + K), 1)
    f.risk_score = round(max(0.0, min(100.0, f.base_score + (f.ai_adjustment or 0.0))), 1)
    f.score_factors = {
        "technical": round(tech * 10, 1),
        "technical_source": "cvss" if f.cvss_score is not None else "severity",
        "likelihood": round(lik, 3),
        "likelihood_source": lik_source,
        **(biz_factors or {}),
    }


def aggregate_repo_score(scores: list[float]) -> float:
    """Probabilistic OR over cubed scores: a few severe findings dominate; many low ones add up slowly."""
    p = 1.0
    for s in scores:
        p *= 1.0 - (s / 100.0) ** 3
    return round(100 * (1.0 - p), 1)


def apply_intel(session: Session, findings: list[Finding]) -> None:
    cves = {f.cve for f in findings if f.cve}
    if not cves:
        return
    intel = {r.cve: r for r in session.scalars(select(CveIntel).where(CveIntel.cve.in_(cves)))}
    for f in findings:
        row = intel.get(f.cve) if f.cve else None
        if not row:
            continue
        if row.cvss_score is not None and f.cvss_score is None:
            f.cvss_score = row.cvss_score
        f.epss_score, f.epss_percentile, f.in_kev = row.epss_score, row.epss_percentile, row.in_kev


def rescore_repo(session: Session, repo: Repository) -> None:
    findings = list(session.scalars(select(Finding).where(Finding.repository_id == repo.id)))
    apply_intel(session, findings)
    biz, factors = business_multiplier(repo)
    for f in findings:
        score_finding(f, repo, biz, factors)
    repo.risk_score = aggregate_repo_score([f.risk_score for f in findings if f.status in ACTIVE])
    session.commit()


def rescore_all(session: Session) -> None:
    for repo in session.scalars(select(Repository)).all():
        rescore_repo(session, repo)


def sla_days(score: float) -> int:
    """Suggested remediation SLA from risk score."""
    if score >= 85:
        return 7
    if score >= 65:
        return 30
    if score >= 40:
        return 90
    return 180


