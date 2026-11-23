"""SCA formats: Trivy JSON, Grype JSON."""

from .base import ParsedFinding, clean_cwes, normalize_severity


def parse_trivy(doc: dict) -> list[ParsedFinding]:
    findings = []
    for result in doc.get("Results", []) or []:
        target = result.get("Target")
        for v in result.get("Vulnerabilities", []) or []:
            cvss = None
            for src in (v.get("CVSS") or {}).values():
                cvss = src.get("V3Score") or src.get("V40Score") or cvss
                if cvss:
                    break
            vid = v.get("VulnerabilityID")
            findings.append(
                ParsedFinding(
                    scan_type="sca",
                    tool="trivy",
                    rule_id=vid,
                    cve=vid if vid and vid.startswith("CVE-") else _first_cve(v.get("VendorIDs")),
                    title=v.get("Title") or f"{vid} in {v.get('PkgName')}",
                    description=v.get("Description"),
                    severity=normalize_severity(v.get("Severity")),
                    cwe=clean_cwes(v.get("CweIDs")),
                    package=v.get("PkgName"),
                    installed_version=v.get("InstalledVersion"),
                    fixed_version=v.get("FixedVersion"),
                    file_path=target,
                    cvss_score=cvss,
                )
            )
    return findings


def parse_grype(doc: dict) -> list[ParsedFinding]:
    findings = []
    for m in doc.get("matches", []) or []:
        vuln = m.get("vulnerability", {})
        art = m.get("artifact", {})
        vid = vuln.get("id")
        cve = vid if vid and vid.startswith("CVE-") else None
        if not cve:
            cve = _first_cve([r.get("id") for r in m.get("relatedVulnerabilities", []) or []])
        cvss = None
        for c in vuln.get("cvss", []) or []:
            cvss = (c.get("metrics") or {}).get("baseScore") or cvss
        fix = vuln.get("fix", {}) or {}
        locs = art.get("locations") or []
        findings.append(
            ParsedFinding(
                scan_type="sca",
                tool="grype",
                rule_id=vid,
                cve=cve,
                title=f"{vid} in {art.get('name')}",
                description=vuln.get("description"),
                severity=normalize_severity(vuln.get("severity")),
                package=art.get("name"),
                installed_version=art.get("version"),
                fixed_version=", ".join(fix.get("versions") or []) or None,
                file_path=locs[0].get("path") if locs else None,
                cvss_score=cvss,
            )
        )
    return findings


def _first_cve(ids) -> str | None:
    for i in ids or []:
        if isinstance(i, str) and i.startswith("CVE-"):
            return i
    return None
