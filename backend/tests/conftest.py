import os

os.environ["RISK_RUNNER_DATABASE_URL"] = "sqlite://"  # overridden per test below
os.environ["RISK_RUNNER_ENRICHMENT_ENABLED"] = "false"
os.environ["RISK_RUNNER_INGEST_TOKEN"] = "test-token"

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from risk_runner import db

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture(autouse=True)
def fresh_db(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(db, "engine", engine)
    monkeypatch.setattr(db, "SessionLocal", factory)
    from risk_runner import app as app_module

    monkeypatch.setattr(app_module, "SessionLocal", factory)
    db.Base.metadata.create_all(engine)
    yield factory


@pytest.fixture
def session(fresh_db):
    with fresh_db() as s:
        yield s


@pytest.fixture
def client(fresh_db):
    from risk_runner.app import app

    def _session():
        with fresh_db() as s:
            yield s

    app.dependency_overrides[db.get_session] = _session
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
