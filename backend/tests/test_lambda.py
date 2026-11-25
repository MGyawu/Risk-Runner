import json

import boto3
import pytest
from conftest import FIXTURES
from moto import mock_aws

from risk_runner import lambda_handlers as lh
from risk_runner.config import settings
from risk_runner.models import Finding, Scan

BUCKET = "test-reports"
AUTH = {"Authorization": "Bearer test-token"}


@pytest.fixture
def s3(monkeypatch):
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setattr(settings, "reports_bucket", BUCKET)
    monkeypatch.setattr(lh, "_s3_client", None)
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET)
        yield client


def api(method, path, body=None, headers=AUTH, path_id=None):
    route = "POST /uploads" if method == "POST" else "GET /uploads/{id}"
    event = {"routeKey": route, "headers": headers, "body": json.dumps(body) if body is not None else None}
    if path_id is not None:
        event["pathParameters"] = {"id": path_id}
    resp = lh.api_handler(event)
    return resp["statusCode"], json.loads(resp["body"])


def sqs_event(*upload_ids):
    records = [{"s3": {"object": {"key": f"reports/{uid}.json"}}} for uid in upload_ids]
    return {"Records": [{"messageId": "m1", "body": json.dumps({"Records": records})}]}


def create_and_upload(s3, report: bytes, **meta):
    status, body = api("POST", "/uploads", {"repository": "acme/shop", "branch": "main", **meta})
    assert status == 201, body
    uid = body["upload_id"]
    assert body["upload"]["fields"]["key"] == f"reports/{uid}.json"
    s3.put_object(Bucket=BUCKET, Key=f"reports/{uid}.json", Body=report)
    return uid


def test_requires_token(s3):
    assert api("POST", "/uploads", {"repository": "acme/shop"}, headers={})[0] == 401
    assert api("POST", "/uploads", {"repository": "acme/shop"}, headers={"Authorization": "Bearer nope"})[0] == 401


def test_validates_metadata(s3):
    assert api("POST", "/uploads", {"repository": "not a repo"})[0] == 422
    assert api("POST", "/uploads", {"repository": "acme/shop", "format": "csv"})[0] == 422
    assert api("POST", "/uploads", {"repository": "acme/shop", "scan_type": "iast"})[0] == 422


def test_unknown_upload_is_404(s3):
    assert api("GET", "", path_id="0" * 32)[0] == 404
    assert api("GET", "", path_id="../meta/x")[0] == 404


def test_upload_processed_end_to_end(s3, session):
    uid = create_and_upload(s3, (FIXTURES / "trivy.json").read_bytes())
    assert api("GET", "", path_id=uid) == (200, {"status": "pending"})

    assert lh.process_handler(sqs_event(uid)) == {"batchItemFailures": []}

    status, result = api("GET", "", path_id=uid)
    assert status == 200 and result["status"] == "done"
    assert result["repository"] == "acme/shop"
    assert result["scan"]["scan_type"] == "sca" and result["scan"]["finding_count"] == 2
    assert result["repository_risk_score"] > 0
    assert session.query(Finding).count() == 2

    # SQS delivers at least once: a second delivery must not record the scan twice
    lh.process_handler(sqs_event(uid))
    assert session.query(Scan).count() == 1


def test_bad_report_marks_upload_failed(s3, session):
    uid = create_and_upload(s3, b"not json")
    assert lh.process_handler(sqs_event(uid)) == {"batchItemFailures": []}  # no retry
    status, result = api("GET", "", path_id=uid)
    assert result["status"] == "failed" and "not valid JSON" in result["error"]

    uid = create_and_upload(s3, json.dumps({"something": "else"}).encode())
    lh.process_handler(sqs_event(uid))
    assert api("GET", "", path_id=uid)[1]["status"] == "failed"
    assert session.query(Scan).count() == 0


def test_s3_test_event_is_ignored(s3):
    event = {"Records": [{"messageId": "m1", "body": json.dumps({"Event": "s3:TestEvent"})}]}
    assert lh.process_handler(event) == {"batchItemFailures": []}


def test_database_errors_are_retried(s3, monkeypatch):
    uid = create_and_upload(s3, (FIXTURES / "trivy.json").read_bytes())

    def boom(*a, **kw):
        raise RuntimeError("database unavailable")

    monkeypatch.setattr("risk_runner.ingest.ingest_report", boom)
    assert lh.process_handler(sqs_event(uid)) == {"batchItemFailures": [{"itemIdentifier": "m1"}]}
    assert api("GET", "", path_id=uid)[1] == {"status": "pending"}


def test_pending_enrichment_picks_up_new_cves(client, monkeypatch):
    from risk_runner import app as app_module

    with open(FIXTURES / "trivy.json", "rb") as fh:
        client.post("/api/v1/ingest", headers=AUTH, files={"report": fh}, data={"repository": "acme/shop"})
    seen = []
    monkeypatch.setattr(app_module, "enrich_and_rescore", lambda cves=None: seen.append(sorted(cves)))
    app_module.enrich_pending()
    assert seen and all(c.startswith("CVE-") for c in seen[0])
