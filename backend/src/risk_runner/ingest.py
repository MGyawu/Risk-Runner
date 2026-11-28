"""Ingest a scanner report: parse, dedupe, track lifecycle, score."""

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import Finding, FindingStatus, Repository, Scan, utcnow
from .parsers import parse_report
from .scoring import rescore_repo


def lock_repository(session: Session, full_name: str) -> None:
    """Make ingests of one repository take turns until this transaction commits or rolls back.

    Ingest reads the repository's findings, decides what's new or fixed, then writes. Two uploads
    for the same repository at once (web server and Lambda, or two Lambdas) could otherwise both
    create the repository or the same finding, or close findings the other just saw. Uploads for
    different repositories don't wait for each other. SQLite (tests, local dev) has no advisory
    locks and serializes writes itself, so this is skipped there.
    """
    if session.get_bind().dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:name))"), {"name": full_name})


def get_or_create_repo(session: Session, full_name: str) -> Repository:
    repo = session.scalar(select(Repository).where(Repository.full_name == full_name))
    if repo is None:
        repo = Repository(full_name=full_name, compliance=[])
        session.add(repo)
        session.flush()
    return repo


def ingest_report(
    session: Session,
    *,
    repository: str,
    document: dict,
    fmt: str | None = None,
    scan_type: str | None = None,
    tool: str | None = None,
    branch: str | None = None,
    commit_sha: str | None = None,
    workflow_run_url: str | None = None,
    default_branch: str | None = None,
) -> tuple[Scan, list[str]]:
    """Returns the scan record and the CVEs it referenced (for enrichment)."""
    fmt, scan_type, parsed = parse_report(document, fmt, scan_type)
    if tool:
        for p in parsed:
            p.tool = tool
    tool_name = tool or (parsed[0].tool if parsed else fmt)

    lock_repository(session, repository)  # waits here while another upload is writing this repository
    repo = get_or_create_repo(session, repository)
    if default_branch:  # reported by the uploader (GitHub knows the real default branch)
        repo.default_branch = default_branch
    now = utcnow()
    # Posture reflects the default branch. Other branches (PRs, feature work) are recorded as scans
    # with their counts but don't create or close findings.
    affects_posture = branch is None or branch == repo.default_branch
    existing = {
        f.fingerprint: f
        for f in session.scalars(
            select(Finding).where(Finding.repository_id == repo.id, Finding.scan_type == scan_type, Finding.tool == tool_name)
        )
    }

    seen: set[str] = set()
    new_count = 0
    for p in parsed:
        fp = p.fingerprint()
        if fp in seen:
            continue  # duplicate inside the same report
        seen.add(fp)
        f = existing.get(fp)
        if not affects_posture:
            new_count += f is None
            continue
        if f is None:
            f = Finding(repository_id=repo.id, fingerprint=fp, first_seen=now, status=FindingStatus.OPEN)
            session.add(f)
            existing[fp] = f
            new_count += 1
        elif f.status == FindingStatus.FIXED:
            f.status, f.fixed_at = FindingStatus.OPEN, None  # regression
        f.scan_type, f.tool, f.rule_id, f.title = p.scan_type, p.tool, p.rule_id, p.title
        f.description, f.severity, f.cwe, f.cve = p.description, p.severity, p.cwe, p.cve
        f.file_path, f.line, f.url = p.file_path, p.line, p.url
        f.package, f.installed_version, f.fixed_version = p.package, p.installed_version, p.fixed_version
        if p.cvss_score is not None:
            f.cvss_score = p.cvss_score
        f.last_seen = now

    fixed_count = 0
    if affects_posture:
        for fp, f in existing.items():
            if fp not in seen and f.status == FindingStatus.OPEN:
                f.status, f.fixed_at = FindingStatus.FIXED, now
                fixed_count += 1

    scan = Scan(
        repository_id=repo.id,
        scan_type=scan_type,
        tool=tool_name,
        format=fmt,
        branch=branch,
        commit_sha=commit_sha,
        workflow_run_url=workflow_run_url,
        finding_count=len(seen),
        new_count=new_count,
        fixed_count=fixed_count,
    )
    session.add(scan)
    session.commit()  # releases the lock
    rescore_repo(session, repo)
    return scan, sorted({p.cve for p in parsed if p.cve})
