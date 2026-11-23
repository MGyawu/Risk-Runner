from conftest import load

from risk_runner.parsers import detect_format, parse_report


def test_detects_formats():
    assert detect_format(load("codeql.sarif")) == "sarif"
    assert detect_format(load("trivy.json")) == "trivy"
    assert detect_format(load("grype.json")) == "grype"
    assert detect_format(load("zap.json")) == "zap"


def test_sarif_codeql():
    fmt, scan_type, findings = parse_report(load("codeql.sarif"))
    assert (fmt, scan_type) == ("sarif", "sast")
    sqli = findings[0]
    assert sqli.tool == "CodeQL"
    assert sqli.severity == "high"  # security-severity 8.8
    assert sqli.cwe == ["CWE-89"]
    assert (sqli.file_path, sqli.line) == ("src/api/orders.js", 42)
    assert findings[1].severity == "medium"


def test_trivy():
    _, scan_type, findings = parse_report(load("trivy.json"))
    assert scan_type == "sca"
    log4j = findings[0]
    assert log4j.cve == "CVE-2021-44228"
    assert log4j.cvss_score == 10.0
    assert (log4j.package, log4j.installed_version, log4j.fixed_version) == ("log4j-core", "2.14.1", "2.17.1")
    assert findings[1].cvss_score is None


def test_grype_maps_ghsa_to_related_cve():
    _, _, findings = parse_report(load("grype.json"))
    assert findings[0].cve == "CVE-2020-8203"
    assert findings[0].severity == "high"


def test_zap_one_finding_per_instance():
    _, scan_type, findings = parse_report(load("zap.json"))
    assert scan_type == "dast"
    assert len(findings) == 3
    assert findings[0].severity == "high" and findings[0].cwe == ["CWE-89"]
    assert findings[0].description == "SQL injection may be possible."


def test_fingerprint_ignores_line_and_query():
    _, _, a = parse_report(load("codeql.sarif"))
    moved = load("codeql.sarif")
    moved["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] = 99
    _, _, b = parse_report(moved)
    assert a[0].fingerprint() == b[0].fingerprint()


def _sarif_hits(*hits):
    """hits: (file, line, snippet or None)"""
    results = []
    for file, line, snippet in hits:
        region = {"startLine": line, **({"snippet": {"text": snippet}} if snippet else {})}
        results.append({
            "ruleId": "rule.x",
            "message": {"text": "Same message"},
            "fingerprints": {"matchBasedId/v1": "requires login"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": file}, "region": region}}],
        })
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep OSS"}}, "results": results}]}


def test_multiple_hits_of_one_rule_in_one_file_are_kept():
    _, _, findings = parse_report(_sarif_hits(("a.py", 1, "eval(x)"), ("a.py", 9, "eval(y)"), ("a.py", 20, "eval(x)")))
    assert len({f.fingerprint() for f in findings}) == 3


def test_snippet_fingerprint_survives_line_moves():
    _, _, before = parse_report(_sarif_hits(("a.py", 1, "eval(x)"), ("a.py", 9, "eval(y)")))
    _, _, after = parse_report(_sarif_hits(("a.py", 30, "eval(x)"), ("a.py", 41, "eval(y)")))
    assert {f.fingerprint() for f in before} == {f.fingerprint() for f in after}


def test_hits_without_snippets_are_kept_and_numbered():
    _, _, findings = parse_report(_sarif_hits(("a.py", 1, None), ("a.py", 9, None)))
    assert len({f.fingerprint() for f in findings}) == 2
