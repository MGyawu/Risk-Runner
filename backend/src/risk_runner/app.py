import asyncio
import json
import logging
from collections import Counter
from contextlib import asynccontextmanager
from datetime import UTC, timedelta
from pathlib import Path
from typing import Annotated, Literal

from fastapi import BackgroundTasks, Depends, FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import ai, intel, schemas
from .auth import require_api_token, require_ingest_token
from .config import settings
from .db import SessionLocal, get_session, init_db
from .ingest import ingest_report
from .models import CveIntel, Finding, FindingStatus, Repository, Scan, utcnow
from .parsers import FORMATS, UnsupportedFormat
from .scoring import ACTIVE, rescore_all, rescore_repo, sla_days

log = logging.getLogger("risk_runner")
logging.basicConfig(level=logging.INFO)
MAX_REPORT_BYTES = 50 * 1024 * 1024
DbSession = Annotated[Session, Depends(get_session)]


def risk_band(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


# ---------------------------------------------------------------- background jobs


def enrich_and_rescore(cves: list[str] | None = None) -> None:
    with SessionLocal() as session:
        if cves is None:
            cves = list(session.scalars(select(Finding.cve).where(Finding.cve.is_not(None)).distinct()))
        try:
            intel.refresh_intel(session, cves)
        except Exception:  # never let enrichment failures break ingestion
            log.exception("Threat intel refresh failed")
        rescore_all(session)


def enrich_pending() -> None:
    """Enrich CVEs that have no intel yet (reports ingested by Lambda, which has no internet access)."""
    with SessionLocal() as session:
        cves = list(
            session.scalars(
                select(func.upper(Finding.cve))
                .outerjoin(CveIntel, CveIntel.cve == func.upper(Finding.cve))
                .where(Finding.cve.is_not(None), CveIntel.cve.is_(None))
                .distinct()
            )
        )
    if cves:
        log.info("Enriching %d new CVEs", len(cves))
        enrich_and_rescore(cves)


async def _periodic_enrichment() -> None:
    while True:
        await asyncio.sleep(settings.enrichment_interval_hours * 3600)
        await run_in_threadpool(enrich_and_rescore)


async def _pending_enrichment() -> None:
    while True:
        await asyncio.sleep(settings.pending_enrichment_minutes * 60)
        try:
            await run_in_threadpool(enrich_pending)
        except Exception:
            log.exception("Pending enrichment failed")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    tasks = []
    if settings.enrichment_enabled:
        tasks = [asyncio.create_task(_periodic_enrichment()), asyncio.create_task(_pending_enrichment())]
    yield
    for task in tasks:
        task.cancel()


app = FastAPI(title="Risk Runner", version="0.1.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["*"], allow_headers=["*"])


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "ai_enabled": settings.ai_enabled}


# ---------------------------------------------------------------- ingestion


@app.post("/api/v1/ingest", response_model=schemas.IngestResult, dependencies=[Depends(require_ingest_token)])
async def ingest(
    background: BackgroundTasks,
    session: DbSession,
    report: UploadFile = File(...),
    repository: str = Form(..., pattern=r"^[\w.-]+/[\w.-]+$"),
    scan_type: Literal["sast", "sca", "dast"] | None = Form(None),
    format: str | None = Form(None),
    tool: str | None = Form(None),
    branch: str | None = Form(None),
    commit_sha: str | None = Form(None),
    workflow_run_url: str | None = Form(None),
    default_branch: str | None = Form(None),
):
    raw = await report.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise HTTPException(413, "Report exceeds 50 MB")
    if format and format not in FORMATS:
        raise HTTPException(422, f"format must be one of {FORMATS}")
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as e:
        raise HTTPException(422, f"Report is not valid JSON: {e}") from e
    try:
        scan, cves = await run_in_threadpool(
            ingest_report,
            session,
            repository=repository,
            document=document,
            fmt=format,
            scan_type=scan_type,
            tool=tool,
            branch=branch,
            commit_sha=commit_sha,
            workflow_run_url=workflow_run_url,
            default_branch=default_branch,
        )
    except UnsupportedFormat as e:
        raise HTTPException(422, str(e)) from e

    if cves and settings.enrichment_enabled:
        background.add_task(enrich_and_rescore, cves)
    repo = session.get(Repository, scan.repository_id)
    return schemas.IngestResult(
        scan=schemas.ScanOut.model_validate(scan),
        repository=repo.full_name,
        repository_risk_score=repo.risk_score,
        cves=len(cves),
    )


# ---------------------------------------------------------------- read API

api = Depends(require_api_token)


def _finding_out(f: Finding, repo_name: str | None = None) -> schemas.FindingOut:
    out = schemas.FindingOut.model_validate(f)
    out.repository_name = repo_name
    out.sla_days = sla_days(f.risk_score) if f.status == FindingStatus.OPEN else None
    return out


@app.get("/api/v1/overview", response_model=schemas.Overview, dependencies=[api])
def overview(session: DbSession):
    repos = session.scalars(select(Repository)).all()
    names = {r.id: r.full_name for r in repos}
    open_findings = session.scalars(select(Finding).where(Finding.status.in_(ACTIVE))).all()
    bands = Counter(risk_band(f.risk_score) for f in open_findings)
    top = sorted(open_findings, key=lambda f: f.risk_score, reverse=True)[:10]

    # 30-day open-findings trend reconstructed from first_seen / fixed_at
    all_findings = session.execute(select(Finding.first_seen, Finding.fixed_at, Finding.status)).all()
    today = utcnow().replace(hour=23, minute=59, second=59)
    trend = []
    for d in range(29, -1, -1):
        day = today - timedelta(days=d)
        count = sum(
            1
            for first, fixed, status in all_findings
            if _aware(first) <= day
            and (fixed is None or _aware(fixed) > day)
            and status in (FindingStatus.OPEN, FindingStatus.FIXED)
        )
        trend.append({"date": day.date().isoformat(), "open": count})

    return schemas.Overview(
        repositories=len(repos),
        open_findings=len(open_findings),
        kev_findings=sum(f.in_kev for f in open_findings),
        portfolio_risk=max((r.risk_score for r in repos), default=0.0),
        by_band=schemas.SeverityCounts(**bands),
        by_type=dict(Counter(f.scan_type for f in open_findings)),
        top_findings=[_finding_out(f, names.get(f.repository_id)) for f in top],
        trend=trend,
    )


def _aware(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


@app.get("/api/v1/repos", response_model=list[schemas.RepoSummary], dependencies=[api])
def list_repos(session: DbSession):
    repos = session.scalars(select(Repository).order_by(Repository.risk_score.desc())).all()
    open_rows = session.execute(
        select(Finding.repository_id, Finding.scan_type, Finding.risk_score, Finding.in_kev).where(Finding.status.in_(ACTIVE))
    ).all()
    last_scans = dict(session.execute(select(Scan.repository_id, func.max(Scan.created_at)).group_by(Scan.repository_id)).all())
    out = []
    for r in repos:
        rows = [row for row in open_rows if row.repository_id == r.id]
        s = schemas.RepoSummary.model_validate(r)
        s.open_findings = len(rows)
        s.kev_findings = sum(row.in_kev for row in rows)
        s.by_type = dict(Counter(row.scan_type for row in rows))
        s.by_band = schemas.SeverityCounts(**Counter(risk_band(row.risk_score) for row in rows))
        s.last_scan_at = last_scans.get(r.id)
        out.append(s)
    return out


def _repo_or_404(session: Session, repo_id: int) -> Repository:
    repo = session.get(Repository, repo_id)
    if repo is None:
        raise HTTPException(404, "Repository not found")
    return repo


@app.get("/api/v1/repos/{repo_id}", response_model=schemas.RepoOut, dependencies=[api])
def get_repo(repo_id: int, session: DbSession):
    return _repo_or_404(session, repo_id)


@app.patch("/api/v1/repos/{repo_id}", response_model=schemas.RepoOut, dependencies=[api])
def update_repo_context(repo_id: int, body: schemas.RepoContextUpdate, session: DbSession):
    repo = _repo_or_404(session, repo_id)
    for key, value in body.model_dump(exclude_unset=True).items():
        setattr(repo, key, value)
    session.commit()
    rescore_repo(session, repo)  # business context changes every score in the repo
    return repo


@app.get("/api/v1/repos/{repo_id}/scans", response_model=list[schemas.ScanOut], dependencies=[api])
def repo_scans(repo_id: int, session: DbSession, limit: int = Query(50, le=500)):
    _repo_or_404(session, repo_id)
    return session.scalars(select(Scan).where(Scan.repository_id == repo_id).order_by(Scan.created_at.desc()).limit(limit)).all()


@app.post("/api/v1/repos/{repo_id}/analyze", dependencies=[api])
def analyze(repo_id: int, session: DbSession):
    repo = _repo_or_404(session, repo_id)
    try:
        return ai.analyze_repo(session, repo)
    except ai.AIUnavailable as e:
        raise HTTPException(503, str(e)) from e


@app.get("/api/v1/findings", response_model=list[schemas.FindingOut], dependencies=[api])
def list_findings(
    session: DbSession,
    repo_id: int | None = None,
    status: FindingStatus | Literal["all"] = FindingStatus.OPEN,
    scan_type: Literal["sast", "sca", "dast"] | None = None,
    kev: bool | None = None,
    min_score: float = 0,
    q: str | None = None,
    limit: int = Query(200, le=1000),
    offset: int = 0,
):
    stmt = select(Finding, Repository.full_name).join(Repository).where(Finding.risk_score >= min_score)
    if repo_id is not None:
        stmt = stmt.where(Finding.repository_id == repo_id)
    if status != "all":
        stmt = stmt.where(Finding.status == status)
    if scan_type:
        stmt = stmt.where(Finding.scan_type == scan_type)
    if kev is not None:
        stmt = stmt.where(Finding.in_kev == kev)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            Finding.title.ilike(like) | Finding.cve.ilike(like) | Finding.package.ilike(like) | Finding.file_path.ilike(like)
        )
    stmt = stmt.order_by(Finding.risk_score.desc()).limit(limit).offset(offset)
    return [_finding_out(f, name) for f, name in session.execute(stmt).all()]


@app.patch("/api/v1/findings/{finding_id}", response_model=schemas.FindingOut, dependencies=[api])
def update_finding(finding_id: int, body: schemas.FindingStatusUpdate, session: DbSession):
    f = session.get(Finding, finding_id)
    if f is None:
        raise HTTPException(404, "Finding not found")
    f.status = body.status
    f.fixed_at = utcnow() if body.status == FindingStatus.FIXED else None
    session.commit()
    rescore_repo(session, f.repository)
    return _finding_out(f, f.repository.full_name)


@app.post("/api/v1/intel/refresh", dependencies=[api])
def refresh_intel(background: BackgroundTasks):
    background.add_task(enrich_and_rescore)
    return {"status": "scheduled"}


@app.get("/api/v1/intel/{cve}", dependencies=[api])
def get_intel(cve: str, session: DbSession):
    row = session.get(CveIntel, cve.upper())
    if row is None:
        raise HTTPException(404, "No intel cached for this CVE")
    return {c.name: getattr(row, c.name) for c in CveIntel.__table__.columns}


# ---------------------------------------------------------------- dashboard (built SPA)

_dist = Path(__file__).resolve().parents[3] / "frontend" / "dist"
if _dist.is_dir():
    app.mount("/assets", StaticFiles(directory=_dist / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        file = (_dist / path).resolve()
        if path and file.is_file() and file.is_relative_to(_dist):
            return FileResponse(file)
        return FileResponse(_dist / "index.html")
