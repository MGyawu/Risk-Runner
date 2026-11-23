"""Scanner output parsers. `parse_report` auto-detects the format when not given."""

from .base import ParsedFinding
from .dast import parse_zap
from .sarif import parse_sarif
from .sca import parse_grype, parse_trivy

FORMATS = ("sarif", "trivy", "grype", "zap")


class UnsupportedFormat(ValueError):
    pass


def detect_format(doc: dict) -> str:
    if "runs" in doc and ("$schema" in doc and "sarif" in str(doc["$schema"]).lower() or "version" in doc):
        return "sarif"
    if "Results" in doc and ("ArtifactName" in doc or "SchemaVersion" in doc):
        return "trivy"
    if "matches" in doc and "descriptor" in doc:
        return "grype"
    if "site" in doc and ("@programName" in doc or "@version" in doc):
        return "zap"
    raise UnsupportedFormat("Could not detect report format; pass format explicitly")


def default_scan_type(fmt: str) -> str:
    return {"trivy": "sca", "grype": "sca", "zap": "dast"}.get(fmt, "sast")


def parse_report(doc: dict, fmt: str | None = None, scan_type: str | None = None) -> tuple[str, str, list[ParsedFinding]]:
    fmt = fmt or detect_format(doc)
    scan_type = scan_type or default_scan_type(fmt)
    match fmt:
        case "sarif":
            findings = parse_sarif(doc, scan_type)
        case "trivy":
            findings = parse_trivy(doc)
        case "grype":
            findings = parse_grype(doc)
        case "zap":
            findings = parse_zap(doc)
        case _:
            raise UnsupportedFormat(f"Unsupported format: {fmt}. Supported: {', '.join(FORMATS)}")
    # SARIF can carry SCA results (e.g. Snyk Open Source, Trivy --format sarif)
    for f in findings:
        f.scan_type = scan_type if fmt == "sarif" else f.scan_type
    return fmt, scan_type, findings


__all__ = ["FORMATS", "ParsedFinding", "UnsupportedFormat", "detect_format", "parse_report"]
