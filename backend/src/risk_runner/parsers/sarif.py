"""SARIF 2.1.0 — CodeQL, Semgrep, Bandit, Checkmarx, Snyk Code, ZAP (sarif), etc."""

from .base import ParsedFinding, clean_cwes, find_cve, normalize_severity, severity_from_cvss


def parse_sarif(doc: dict, scan_type: str) -> list[ParsedFinding]:
    findings: list[ParsedFinding] = []
    for run in doc.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool = driver.get("name", "sarif")
        rules = {r.get("id"): r for r in driver.get("rules", []) or []}
        # Rules in extensions (CodeQL query packs)
        for ext in run.get("tool", {}).get("extensions", []) or []:
            for r in ext.get("rules", []) or []:
                rules.setdefault(r.get("id"), r)

        for res in run.get("results", []):
            rule_id = res.get("ruleId") or res.get("rule", {}).get("id")
            rule = rules.get(rule_id, {})
            if rule_id is None and "ruleIndex" in res:
                rule_list = driver.get("rules", [])
                if res["ruleIndex"] < len(rule_list):
                    rule = rule_list[res["ruleIndex"]]
                    rule_id = rule.get("id")
            props = {**(rule.get("properties") or {}), **(res.get("properties") or {})}

            # Severity: CodeQL security-severity (CVSS-like) > explicit property > SARIF level
            sec_sev = props.get("security-severity")
            cvss = None
            try:
                cvss = float(sec_sev) if sec_sev is not None else None
            except (TypeError, ValueError):
                pass
            level = res.get("level") or rule.get("defaultConfiguration", {}).get("level")
            severity = severity_from_cvss(cvss) or normalize_severity(
                props.get("severity") or props.get("problem.severity") or level
            )

            message = (res.get("message") or {}).get("text") or ""
            short = (rule.get("shortDescription") or {}).get("text")
            full = (rule.get("fullDescription") or {}).get("text") or (rule.get("help") or {}).get("text")

            file_path = line = url = None
            locs = res.get("locations") or []
            if locs:
                phys = locs[0].get("physicalLocation") or {}
                uri = (phys.get("artifactLocation") or {}).get("uri")
                if uri and uri.startswith(("http://", "https://")):
                    url = uri
                else:
                    file_path = uri
                line = (phys.get("region") or {}).get("startLine")
            # ZAP SARIF puts URLs in webRequest
            if not url and (req := res.get("webRequest")):
                url = req.get("target")

            tags = props.get("tags") or []
            findings.append(
                ParsedFinding(
                    scan_type=scan_type,
                    tool=tool,
                    rule_id=rule_id,
                    title=(short or message or rule_id or "Finding")[:1000],
                    description=(message + ("\n\n" + full if full and full != message else "")).strip() or None,
                    severity=severity,
                    cwe=clean_cwes(tags + list(props.get("cwe", []) if isinstance(props.get("cwe"), list) else [])),
                    cve=find_cve(rule_id, message),
                    file_path=file_path,
                    line=line,
                    url=url,
                    cvss_score=cvss if find_cve(rule_id, message) else None,
                )
            )
    return findings
