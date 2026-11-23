"""Threat intelligence enrichment: FIRST EPSS, CISA KEV, NVD CVSS."""

import logging
import time
from collections.abc import Iterable

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import settings
from .models import CveIntel, utcnow

log = logging.getLogger(__name__)
EPSS_BATCH = 100
NVD_MAX_PER_RUN = 50


def _client() -> httpx.Client:
    return httpx.Client(timeout=30.0, headers={"User-Agent": "risk-runner/0.1"}, follow_redirects=True)


def fetch_epss(cves: list[str], client: httpx.Client) -> dict[str, tuple[float, float]]:
    out: dict[str, tuple[float, float]] = {}
    for i in range(0, len(cves), EPSS_BATCH):
        batch = cves[i : i + EPSS_BATCH]
        r = client.get(settings.epss_url, params={"cve": ",".join(batch)})
        r.raise_for_status()
        for row in r.json().get("data", []):
            out[row["cve"].upper()] = (float(row["epss"]), float(row["percentile"]))
    return out


def fetch_kev(client: httpx.Client) -> dict[str, dict]:
    r = client.get(settings.kev_url)
    r.raise_for_status()
    return {v["cveID"].upper(): v for v in r.json().get("vulnerabilities", [])}


def fetch_nvd_cvss(cve: str, client: httpx.Client) -> tuple[float | None, str | None]:
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    r = client.get(settings.nvd_url, params={"cveId": cve}, headers=headers)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", [])
    if not vulns:
        return None, None
    metrics = vulns[0].get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0] if entries else None)
        if primary:
            data = primary.get("cvssData", {})
            return data.get("baseScore"), data.get("vectorString")
    return None, None


def refresh_intel(session: Session, cves: Iterable[str], *, include_nvd: bool = True) -> int:
    """Refresh EPSS + KEV for the given CVEs and fill missing CVSS from NVD. Returns rows updated."""
    cves = sorted({c.upper() for c in cves if c})
    if not cves:
        return 0
    existing = {row.cve: row for row in session.scalars(select(CveIntel).where(CveIntel.cve.in_(cves)))}
    for cve in cves:
        if cve not in existing:
            existing[cve] = CveIntel(cve=cve)
            session.add(existing[cve])

    with _client() as client:
        try:
            epss = fetch_epss(cves, client)
            for cve, (score, pct) in epss.items():
                if cve in existing:
                    existing[cve].epss_score, existing[cve].epss_percentile = score, pct
        except httpx.HTTPError as e:
            log.warning("EPSS fetch failed: %s", e)
        try:
            kev = fetch_kev(client)
            for cve, row in existing.items():
                entry = kev.get(cve)
                row.in_kev = entry is not None
                row.kev_due_date = entry.get("dueDate") if entry else None
                row.kev_ransomware = bool(entry and entry.get("knownRansomwareCampaignUse") == "Known")
        except httpx.HTTPError as e:
            log.warning("KEV fetch failed: %s", e)

        if include_nvd:
            # NVD is heavily rate limited (5 req/30s without a key); only fetch what we've never fetched.
            todo = [r for r in existing.values() if r.nvd_fetched_at is None][:NVD_MAX_PER_RUN]
            delay = 0.7 if settings.nvd_api_key else 6.5
            for idx, row in enumerate(todo):
                try:
                    row.cvss_score, row.cvss_vector = fetch_nvd_cvss(row.cve, client)
                    row.nvd_fetched_at = utcnow()
                except httpx.HTTPError as e:
                    log.warning("NVD fetch failed for %s: %s", row.cve, e)
                    break
                if idx < len(todo) - 1:
                    time.sleep(delay)
    session.commit()
    return len(existing)
