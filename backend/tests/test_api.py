from conftest import FIXTURES

AUTH = {"Authorization": "Bearer test-token"}


def upload(client, name, repo="acme/shop", **data):
    with open(FIXTURES / name, "rb") as fh:
        return client.post("/api/v1/ingest", headers=AUTH, files={"report": (name, fh)}, data={"repository": repo, **data})


def test_ingest_requires_token(client):
    with open(FIXTURES / "trivy.json", "rb") as fh:
        r = client.post("/api/v1/ingest", files={"report": fh}, data={"repository": "acme/shop"})
    assert r.status_code == 401


def test_ingest_and_dashboard(client):
    for name in ("codeql.sarif", "trivy.json", "zap.json"):
        r = upload(client, name)
        assert r.status_code == 200, r.text
    assert r.json()["scan"]["scan_type"] == "dast"

    ov = client.get("/api/v1/overview").json()
    assert ov["repositories"] == 1
    assert ov["open_findings"] == 2 + 2 + 3
    assert set(ov["by_type"]) == {"sast", "sca", "dast"}
    assert len(ov["trend"]) == 30

    repos = client.get("/api/v1/repos").json()
    assert repos[0]["full_name"] == "acme/shop" and repos[0]["risk_score"] > 0


def test_business_context_rescores(client):
    upload(client, "trivy.json")
    repo = client.get("/api/v1/repos").json()[0]
    before = repo["risk_score"]
    r = client.patch(
        f"/api/v1/repos/{repo['id']}",
        json={"criticality": 5, "exposure": "internet", "data_sensitivity": "restricted", "compliance": ["PCI"]},
    )
    assert r.status_code == 200
    assert r.json()["risk_score"] > before


def test_lifecycle_fix_and_regression(client):
    upload(client, "trivy.json", branch="main")
    # A feature-branch scan with nothing in it must not close anything
    empty = FIXTURES / "trivy.json"
    import json

    doc = json.loads(empty.read_text())
    doc["Results"][0]["Vulnerabilities"] = doc["Results"][0]["Vulnerabilities"][:1]
    r = client.post(
        "/api/v1/ingest",
        headers=AUTH,
        files={"report": ("t.json", json.dumps(doc))},
        data={"repository": "acme/shop", "branch": "feature/x"},
    )
    assert r.json()["scan"]["fixed_count"] == 0
    assert len(client.get("/api/v1/findings").json()) == 2

    # Same partial report on main closes the missing finding
    r = client.post(
        "/api/v1/ingest", headers=AUTH, files={"report": ("t.json", json.dumps(doc))}, data={"repository": "acme/shop", "branch": "main"}
    )
    assert r.json()["scan"]["fixed_count"] == 1
    assert len(client.get("/api/v1/findings").json()) == 1

    # Full report again reopens it
    upload(client, "trivy.json", branch="main")
    assert len(client.get("/api/v1/findings").json()) == 2


def test_finding_triage(client):
    upload(client, "zap.json")
    f = client.get("/api/v1/findings").json()[0]
    r = client.patch(f"/api/v1/findings/{f['id']}", json={"status": "false_positive"})
    assert r.status_code == 200
    assert all(x["id"] != f["id"] for x in client.get("/api/v1/findings").json())


def test_rejects_unknown_format(client):
    r = client.post("/api/v1/ingest", headers=AUTH, files={"report": ("x.json", b'{"foo": 1}')}, data={"repository": "acme/shop"})
    assert r.status_code == 422


def test_analyze_disabled(client):
    upload(client, "trivy.json")
    repo = client.get("/api/v1/repos").json()[0]
    assert client.post(f"/api/v1/repos/{repo['id']}/analyze").status_code == 503


def test_default_branch_reported_by_uploader(client):
    upload(client, "trivy.json", repo="juice/shop", branch="master", default_branch="master")
    assert len(client.get("/api/v1/findings").json()) == 2
    assert client.get("/api/v1/repos").json()[0]["default_branch"] == "master"
