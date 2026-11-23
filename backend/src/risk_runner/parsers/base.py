import hashlib
import re
from dataclasses import dataclass, field

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class ParsedFinding:
    scan_type: str
    tool: str
    title: str
    severity: str = "medium"
    rule_id: str | None = None
    description: str | None = None
    cwe: list[str] = field(default_factory=list)
    cve: str | None = None
    file_path: str | None = None
    line: int | None = None
    url: str | None = None
    package: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    cvss_score: float | None = None
    # Distinguishes several hits of one rule in one file (tool fingerprint or code snippet).
    location_key: str | None = None

    def fingerprint(self) -> str:
        """Stable identity across scans. Line numbers are excluded so code drift doesn't reopen findings."""
        if self.scan_type == "sca":
            parts = [self.scan_type, self.cve or self.rule_id or self.title, self.package, self.installed_version]
        elif self.scan_type == "dast":
            parts = [self.scan_type, self.rule_id or self.title, _strip_query(self.url)]
        else:
            parts = [self.scan_type, self.rule_id or self.title, self.file_path, self.title, self.location_key]
        return hashlib.sha256("|".join(p or "" for p in parts).encode()).hexdigest()


def disambiguate(findings: list[ParsedFinding]) -> None:
    """Number repeated identical location keys (same rule, file and code) so each hit is kept."""
    seen: dict[tuple, int] = {}
    for f in findings:
        if f.scan_type != "sast" or f.location_key is None:
            continue  # only SARIF-sourced SAST hits carry a location key
        key = (f.rule_id, f.file_path, f.location_key)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > 1:
            f.location_key = f"{f.location_key}#{seen[key]}"


def normalize_severity(value: object) -> str:
    v = str(value or "").strip().lower()
    aliases = {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
        "informational": "info",
        "negligible": "info",
        "unknown": "medium",
        "moderate": "medium",
    }
    v = aliases.get(v, v)
    return v if v in SEVERITIES else "medium"


def severity_from_cvss(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def find_cve(*texts: object) -> str | None:
    for t in texts:
        if t and (m := CVE_RE.search(str(t))):
            return m.group(0).upper()
    return None


def _strip_query(url: str | None) -> str | None:
    return url.split("?", 1)[0] if url else url


def clean_cwes(values) -> list[str]:
    """Normalize 'CWE-79', 'external/cwe/cwe-079', '79', 79 -> 'CWE-79'. Ignores unrelated tags."""
    out = set()
    for v in values or []:
        s = str(v).strip().lower()
        m = re.search(r"cwe[-_/ ]?0*(\d+)", s) or re.fullmatch(r"0*(\d+)", s)
        if m:
            out.add(f"CWE-{m.group(1)}")
    return sorted(out)
