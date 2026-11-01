"""PostgreSQL migration and guard checks. Skipped unless PRAMANA_TEST_PG_URL points at a DISPOSABLE database.

    docker run --rm -d --name pramana-pg-test -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:16-alpine
    PRAMANA_TEST_PG_URL=postgresql+psycopg2://postgres:test@localhost:55432/postgres pytest tests/test_postgres_migration.py

The test drops and recreates the `public` schema of that database.
"""
from __future__ import annotations

import os
import threading
from datetime import datetime

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from app.db.migrate import migrate
from app.db.models import compute_entry_hash
from app.db.runs import create_analysis_run
from app.db.session import format_custody_time, verify_custody_log

PG_URL = os.getenv("PRAMANA_TEST_PG_URL")
pytestmark = pytest.mark.skipif(not PG_URL, reason="PRAMANA_TEST_PG_URL not set (needs a disposable PostgreSQL >= 14)")

PRE_T3_DDL = [
    "CREATE TABLE cases (case_id VARCHAR(64) PRIMARY KEY, name VARCHAR(255) NOT NULL, created_at TIMESTAMP NOT NULL)",
    """CREATE TABLE evidence (evidence_id VARCHAR(64) PRIMARY KEY, case_id VARCHAR(64) NOT NULL REFERENCES cases,
       filename VARCHAR(255) NOT NULL, sha256 VARCHAR(64) NOT NULL, size_bytes INTEGER NOT NULL,
       intake_time TIMESTAMP NOT NULL, stored_path VARCHAR(1024))""",
    """CREATE TABLE findings (finding_id VARCHAR(64) PRIMARY KEY, case_id VARCHAR(64) NOT NULL REFERENCES cases,
       type VARCHAR(32) NOT NULL, claim TEXT NOT NULL, confidence FLOAT NOT NULL, evidence_event_ids JSON NOT NULL,
       reasoning TEXT, alternatives JSON, needs_human_review BOOLEAN NOT NULL, status VARCHAR(32) NOT NULL,
       created_at TIMESTAMP NOT NULL)""",
    """CREATE TABLE events (event_id VARCHAR(64) PRIMARY KEY, case_id VARCHAR(64) NOT NULL REFERENCES cases,
       evidence_id VARCHAR(64) NOT NULL REFERENCES evidence, artifact_ref VARCHAR(512) NOT NULL,
       sha256 VARCHAR(64) NOT NULL, timestamp TIMESTAMP NOT NULL, source VARCHAR(32) NOT NULL, device VARCHAR(255),
       actor VARCHAR(255), action VARCHAR(128) NOT NULL, object VARCHAR(512), ip VARCHAR(64), location JSON, raw JSON)""",
    """CREATE TABLE custody_entries (id SERIAL PRIMARY KEY, evidence_id VARCHAR(64) NOT NULL REFERENCES evidence,
       actor VARCHAR(128) NOT NULL, action VARCHAR(128) NOT NULL, time TIMESTAMP NOT NULL,
       sha256 VARCHAR(64) NOT NULL, prev_hash VARCHAR(64) NOT NULL, entry_hash VARCHAR(64) NOT NULL)""",
]
SHA = "a" * 64
T0 = datetime(2026, 10, 18, 2, 17, 0)


@pytest.fixture
def pg_engine():
    engine = create_engine(PG_URL)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
        for ddl in PRE_T3_DDL:
            conn.execute(text(ddl))
        genesis = compute_entry_hash("0" * 64, "EVID-001", "Intake", "Acquired", format_custody_time(T0), SHA)
        conn.execute(text("INSERT INTO cases VALUES ('CASE-PG', 'pg', :t)"), {"t": T0})
        conn.execute(text("INSERT INTO evidence VALUES ('EVID-001', 'CASE-PG', 'log.csv', :s, 1, :t, NULL)"),
                     {"s": SHA, "t": T0})
        conn.execute(text("INSERT INTO events (event_id, case_id, evidence_id, artifact_ref, sha256, timestamp, "
                          "source, action) VALUES ('EV-1', 'CASE-PG', 'EVID-001', 'log.csv#row=1', :s, :t, 'log', "
                          "'login')"), {"s": SHA, "t": T0})
        conn.execute(text("INSERT INTO custody_entries (evidence_id, actor, action, time, sha256, prev_hash, "
                          "entry_hash) VALUES ('EVID-001', 'Intake', 'Acquired', :t, :s, :p, :h)"),
                     {"t": T0, "s": SHA, "p": "0" * 64, "h": genesis})
    yield engine
    engine.dispose()


def test_pg_migrate_existing_database(pg_engine):
    added = migrate(pg_engine)
    assert {"evidence.status", "evidence.verify_state", "events.family"} <= set(added)
    assert migrate(pg_engine) == []  # idempotent
    with pg_engine.connect() as conn:
        names = {r[0] for r in conn.execute(text("SELECT tgname FROM pg_trigger WHERE NOT tgisinternal"))}
        assert {"trg_evidence_no_delete", "trg_analysis_run_validate", "trg_claim_sealed_run"} <= names
    db = sessionmaker(bind=pg_engine)()
    try:
        assert verify_custody_log(db, "EVID-001")[0]
    finally:
        db.close()


def test_pg_guards(pg_engine):
    migrate(pg_engine)
    for sql in ("DELETE FROM evidence", "UPDATE evidence SET sha256 = 'b'", "TRUNCATE custody_entries CASCADE",
                "UPDATE evidence SET status = 'VERIFIED'"):
        with pg_engine.connect() as conn, pytest.raises(DBAPIError, match="PRAMANA"):
            conn.execute(text(sql))

    db = sessionmaker(bind=pg_engine)()
    try:
        run = create_analysis_run(db, "CASE-PG", engine_version="e@1", assumptions={})
        db.commit()
        with pytest.raises(DBAPIError, match="PRAMANA"):
            db.execute(text("INSERT INTO hypothesis_eval (run_id) VALUES (:r)"), {"r": run.run_id})
        db.rollback()
        with pytest.raises(DBAPIError, match="PRAMANA"):
            db.execute(text("UPDATE analysis_run SET ranking_hash = 'x'"))
        db.rollback()
    finally:
        db.close()


def test_pg_concurrent_migrations_serialize(pg_engine):
    errors: list[BaseException] = []

    def worker():
        try:
            migrate(create_engine(PG_URL))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
