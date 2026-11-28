"""The per-repository ingest lock. Needs a real Postgres (SQLite has no advisory locks):

    docker run --rm -d -p 5433:5432 -e POSTGRES_PASSWORD=test postgres:17
    RISK_RUNNER_TEST_POSTGRES_URL=postgresql+psycopg://postgres:test@localhost:5433/postgres uv run pytest tests/test_ingest_lock.py

Skipped when RISK_RUNNER_TEST_POSTGRES_URL isn't set.
"""

import os
import threading

import pytest
from conftest import load
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from risk_runner import db
from risk_runner.ingest import ingest_report, lock_repository
from risk_runner.models import Repository

URL = os.environ.get("RISK_RUNNER_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not URL, reason="set RISK_RUNNER_TEST_POSTGRES_URL to run against Postgres")


@pytest.fixture
def pg():
    engine = create_engine(URL)
    db.Base.metadata.drop_all(engine)
    db.Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine, expire_on_commit=False)
    db.Base.metadata.drop_all(engine)
    engine.dispose()


def _ingest_in_thread(factory, repository: str, errors: list) -> threading.Thread:
    def run():
        try:
            with factory() as s:
                ingest_report(s, repository=repository, document=load("trivy.json"))
        except Exception as e:  # noqa: BLE001 - surfaced by the test
            errors.append(e)

    t = threading.Thread(target=run)
    t.start()
    return t


def test_same_repository_waits_until_the_first_ingest_commits(pg):
    errors: list = []
    with pg() as holder:
        lock_repository(holder, "acme/api")  # an ingest of acme/api is in progress

        same = _ingest_in_thread(pg, "acme/api", errors)
        other = _ingest_in_thread(pg, "acme/web", errors)

        other.join(timeout=10)
        assert not other.is_alive(), "a different repository must not wait"
        same.join(timeout=1)
        assert same.is_alive(), "the same repository must wait for the lock"

        holder.commit()  # releases the lock
    same.join(timeout=10)
    assert not same.is_alive()
    assert errors == []


def test_simultaneous_uploads_create_one_repository(pg):
    errors: list = []
    threads = [_ingest_in_thread(pg, "acme/api", errors) for _ in range(4)]
    for t in threads:
        t.join(timeout=30)
    assert errors == []
    with pg() as s:
        assert s.scalar(select(func.count()).select_from(Repository)) == 1
