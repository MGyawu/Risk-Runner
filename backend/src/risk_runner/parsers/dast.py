"""DAST: OWASP ZAP traditional JSON report (zap-baseline / zap-full-scan `-J report.json`)."""

import html
import re

from .base import ParsedFinding, clean_cwes

ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}


def _strip_html(text: str | None) -> str | None:
    if not text:
        return text
    return html.unescape(re.sub(r"<[^>]+>", "", text)).strip()


def parse_zap(doc: dict) -> list[ParsedFinding]:
    findings = []
    for site in doc.get("site", []) or []:
        for alert in site.get("alerts", []) or []:
            sev = ZAP_RISK.get(str(alert.get("riskcode")), "medium")
            cwe = [f"CWE-{alert['cweid']}"] if str(alert.get("cweid", "-1")) not in ("-1", "0", "") else []
            instances = alert.get("instances") or [{"uri": site.get("@name")}]
            for inst in instances:
                findings.append(
                    ParsedFinding(
                        scan_type="dast",
                        tool="zap",
                        rule_id=str(alert.get("pluginid") or alert.get("alertRef") or alert.get("name")),
                        title=alert.get("name") or alert.get("alert") or "ZAP alert",
                        description=_strip_html(alert.get("desc")),
                        severity=sev,
                        cwe=clean_cwes(cwe),
                        url=inst.get("uri"),
                    )
                )
    return findings
