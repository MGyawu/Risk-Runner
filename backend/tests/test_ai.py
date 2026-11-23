import json
from types import SimpleNamespace

from conftest import load

from risk_runner import ai
from risk_runner.config import settings
from risk_runner.ingest import ingest_report
from risk_runner.models import Finding, Repository


class FakeMessages:
    def __init__(self, payload_fn):
        self.payload_fn, self.kwargs = payload_fn, None

    def create(self, **kwargs):
        self.kwargs = kwargs
        body = json.loads(kwargs["messages"][0]["content"])
        text = json.dumps(self.payload_fn(body))
        return SimpleNamespace(stop_reason="end_turn", model=kwargs["model"], content=[SimpleNamespace(type="text", text=text)])


def test_analyze_applies_bounded_adjustments(session, monkeypatch):
    ingest_report(session, repository="acme/shop", document=load("trivy.json"))
    repo = session.query(Repository).one()

    def respond(body):
        ids = [f["id"] for f in body["findings"]]
        assert body["business_context"]["repository"] == "acme/shop"
        return {"summary": "Upgrade log4j first.", "findings": [{"id": ids[0], "adjustment": 40, "rationale": "RCE"}, {"id": ids[1], "adjustment": -5, "rationale": "dev only"}]}

    fake = FakeMessages(respond)
    monkeypatch.setattr(settings, "ai_enabled", True)
    monkeypatch.setattr(ai.anthropic, "Anthropic", lambda: SimpleNamespace(beta=SimpleNamespace(messages=fake)))

    result = ai.analyze_repo(session, repo)
    assert result["analyzed"] == 2
    assert fake.kwargs["model"] == "claude-opus-5-5"
    assert fake.kwargs["output_config"]["format"]["type"] == "json_schema"
    adjustments = sorted(f.ai_adjustment for f in session.query(Finding))
    assert adjustments == [-5.0, 15.0]  # +40 clamped to +15
    assert repo.ai_summary == "Upgrade log4j first."
