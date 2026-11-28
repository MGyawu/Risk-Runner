"""AWS Lambda entry points for serverless ingestion (deploy/aws/serverless/template.yaml).

Flow:
  1. The GitHub Action calls ``POST /uploads`` (``api_handler``) with the upload's metadata. The
     metadata is saved to ``meta/<id>.json`` and a presigned S3 POST for ``reports/<id>.json`` is
     returned. Reports go straight to S3, so they aren't limited by Lambda's 6 MB payload limit.
  2. S3 notifies SQS, and ``process_handler`` (inside the VPC, next to RDS) parses the report with
     the same ``ingest_report`` the web server uses, then writes ``results/<id>.json``.
  3. The Action polls ``GET /uploads/<id>`` (``api_handler``) until the result is there.

The API function never touches the database, so it runs outside the VPC.
"""

import base64
import json
import logging
import os
import re
import secrets
import uuid
from datetime import UTC, datetime

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from .config import settings
from .parsers import FORMATS

log = logging.getLogger("risk_runner.lambda")
log.setLevel(logging.INFO)

MAX_REPORT_BYTES = 50 * 1024 * 1024
UPLOAD_URL_TTL = 900  # seconds
REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
UPLOAD_ID_RE = re.compile(r"^[0-9a-f]{32}$")
SCAN_TYPES = ("sast", "sca", "dast")
OPTIONAL_FIELDS = ("scan_type", "format", "tool", "branch", "commit_sha", "workflow_run_url", "default_branch")
MAX_FIELD_LEN = 1024

_s3_client = None


def _s3():
    global _s3_client
    if _s3_client is None:
        region = os.environ.get("AWS_REGION", "us-east-1")
        # Regional endpoint: the global one can redirect (and break presigned POSTs) for new buckets.
        _s3_client = boto3.client(
            "s3",
            region_name=region,
            endpoint_url=f"https://s3.{region}.amazonaws.com",
            config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
        )
    return _s3_client


def _meta_key(upload_id: str) -> str:
    return f"meta/{upload_id}.json"


def _report_key(upload_id: str) -> str:
    return f"reports/{upload_id}.json"


def _result_key(upload_id: str) -> str:
    return f"results/{upload_id}.json"


def _get_json(key: str) -> dict | None:
    try:
        obj = _s3().get_object(Bucket=settings.reports_bucket, Key=key)
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "404"):
            return None
        raise
    return json.loads(obj["Body"].read())


def _put_json(key: str, data: dict) -> None:
    _s3().put_object(
        Bucket=settings.reports_bucket, Key=key, Body=json.dumps(data).encode(), ContentType="application/json"
    )


# ---------------------------------------------------------------- HTTP API


def _response(status: int, body: dict) -> dict:
    return {"statusCode": status, "headers": {"content-type": "application/json"}, "body": json.dumps(body)}


def _authorized(event: dict) -> bool:
    if not settings.ingest_token:
        return False  # a public endpoint never runs without a token
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    token = (headers.get("authorization") or "").removeprefix("Bearer ").strip()
    return secrets.compare_digest(token, settings.ingest_token)


def _validate_upload(body: dict) -> tuple[dict | None, str | None]:
    repository = body.get("repository")
    if not isinstance(repository, str) or not REPO_RE.match(repository):
        return None, "repository must look like owner/repo"
    meta: dict = {"repository": repository}
    for field in OPTIONAL_FIELDS:
        value = body.get(field)
        if value in (None, ""):
            continue
        if not isinstance(value, str) or len(value) > MAX_FIELD_LEN:
            return None, f"{field} must be a string of at most {MAX_FIELD_LEN} characters"
        meta[field] = value
    if meta.get("scan_type") and meta["scan_type"] not in SCAN_TYPES:
        return None, f"scan_type must be one of {SCAN_TYPES}"
    if meta.get("format") and meta["format"] not in FORMATS:
        return None, f"format must be one of {FORMATS}"
    return meta, None


def _create_upload(event: dict) -> dict:
    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode()
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        return _response(400, {"detail": "Body must be JSON"})
    if not isinstance(body, dict):
        return _response(400, {"detail": "Body must be a JSON object"})
    meta, error = _validate_upload(body)
    if error:
        return _response(422, {"detail": error})

    upload_id = uuid.uuid4().hex
    meta["created_at"] = datetime.now(UTC).isoformat()
    _put_json(_meta_key(upload_id), meta)
    post = _s3().generate_presigned_post(
        Bucket=settings.reports_bucket,
        Key=_report_key(upload_id),
        Fields={"Content-Type": "application/json"},
        Conditions=[{"Content-Type": "application/json"}, ["content-length-range", 1, MAX_REPORT_BYTES]],
        ExpiresIn=UPLOAD_URL_TTL,
    )
    log.info("Upload %s created for %s", upload_id, meta["repository"])
    return _response(
        201, {"upload_id": upload_id, "upload": post, "status_path": f"/uploads/{upload_id}", "expires_in": UPLOAD_URL_TTL}
    )


def _get_upload(upload_id: str | None) -> dict:
    if not upload_id or not UPLOAD_ID_RE.match(upload_id):
        return _response(404, {"detail": "Upload not found"})
    result = _get_json(_result_key(upload_id))
    if result is not None:
        return _response(200, result)
    if _get_json(_meta_key(upload_id)) is not None:
        return _response(200, {"status": "pending"})
    return _response(404, {"detail": "Upload not found"})


def api_handler(event: dict, context=None) -> dict:
    """HTTP API (payload v2): ``POST /uploads`` and ``GET /uploads/{id}``."""
    if not _authorized(event):
        return _response(401, {"detail": "Invalid or missing bearer token"})
    route = event.get("routeKey", "")
    if route == "POST /uploads":
        return _create_upload(event)
    if route == "GET /uploads/{id}":
        return _get_upload((event.get("pathParameters") or {}).get("id"))
    return _response(404, {"detail": "Not found"})


# ---------------------------------------------------------------- SQS processor

_db_ready = False


class ReportRejected(Exception):
    """The report can't be ingested. Retrying won't help, so the upload is marked failed."""


def process_upload(upload_id: str) -> dict:
    """Ingest one uploaded report. Returns the result written to ``results/<id>.json``."""
    global _db_ready
    from . import db, schemas
    from .ingest import ingest_report
    from .models import Repository
    from .parsers import UnsupportedFormat

    existing = _get_json(_result_key(upload_id))
    if existing and existing.get("status") == "done":
        return existing  # SQS delivers at least once; don't record the scan twice

    try:
        meta = _get_json(_meta_key(upload_id))
        if meta is None:
            raise ReportRejected("upload metadata not found")
        obj = _s3().get_object(Bucket=settings.reports_bucket, Key=_report_key(upload_id))
        if obj["ContentLength"] > MAX_REPORT_BYTES:
            raise ReportRejected("report exceeds 50 MB")
        try:
            document = json.loads(obj["Body"].read())
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise ReportRejected(f"report is not valid JSON: {e}") from e
        if not isinstance(document, dict):
            raise ReportRejected("report must be a JSON object")

        if not _db_ready:
            db.init_db()
            _db_ready = True
        with db.SessionLocal() as session:
            try:
                scan, cves = ingest_report(
                    session,
                    repository=meta["repository"],
                    document=document,
                    fmt=meta.get("format"),
                    scan_type=meta.get("scan_type"),
                    tool=meta.get("tool"),
                    branch=meta.get("branch"),
                    commit_sha=meta.get("commit_sha"),
                    workflow_run_url=meta.get("workflow_run_url"),
                    default_branch=meta.get("default_branch"),
                )
            except (UnsupportedFormat, KeyError, TypeError, ValueError, AttributeError) as e:
                raise ReportRejected(str(e) or type(e).__name__) from e
            repo = session.get(Repository, scan.repository_id)
            result = {
                "status": "done",
                **schemas.IngestResult(
                    scan=schemas.ScanOut.model_validate(scan),
                    repository=repo.full_name,
                    repository_risk_score=repo.risk_score,
                    cves=len(cves),
                ).model_dump(mode="json"),
            }
    except ReportRejected as e:
        log.warning("Upload %s rejected: %s", upload_id, e)
        result = {"status": "failed", "error": str(e)}

    _put_json(_result_key(upload_id), result)
    log.info("Upload %s: %s", upload_id, result["status"])
    return result


def _upload_ids(message_body: str) -> list[str]:
    body = json.loads(message_body)
    ids = []
    for record in body.get("Records", []):  # absent for the s3:TestEvent sent on setup
        key = record.get("s3", {}).get("object", {}).get("key", "")
        m = re.fullmatch(r"reports/([0-9a-f]{32})\.json", key)
        if m:
            ids.append(m.group(1))
    return ids


def process_handler(event: dict, context=None) -> dict:
    """SQS (S3 ObjectCreated notifications). Failed messages are retried, then sent to the DLQ."""
    failures = []
    for message in event.get("Records", []):
        try:
            for upload_id in _upload_ids(message["body"]):
                process_upload(upload_id)
        except Exception:
            log.exception("Message %s failed; it will be retried", message.get("messageId"))
            failures.append({"itemIdentifier": message["messageId"]})
    return {"batchItemFailures": failures}
