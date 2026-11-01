"""T3: additive migration of a pre-T3 database (the schema deployed before T3)."""
from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from app.db import migrate as migrate_mod
from app.db.migrate import MigrationError, migrate
from app.db.models import Evidence, EventModel, compute_entry_hash
from app.db.session import format_custody_time, init_db, verify_custody_log

# Exact DDL of the pre-T3 tables (taken from a database created by the previous models).
PRE_T3_DDL = [
    """CREATE TABLE cases (case_id VARCHAR(64) NOT NULL, name VARCHAR(255) NOT NULL,
       created_at DATETIME NOT NULL, PRIMARY KEY (case_id))""",
    """CREATE TABLE evidence (evidence_id VARCHAR(64) NOT NULL, case_id VARCHAR(64) NOT NULL,
       filename VARCHAR(255) NOT NULL, sha256 VARCHAR(64) NOT NULL, size_bytes INTEGER NOT NULL,
       intake_time DATETIME NOT NULL, stored_path VARCHAR(1024), PRIMARY KEY (evidence_id),
       FOREIGN KEY(case_id) REFERENCES cases (case_id))""",
    """CREATE TABLE findings (finding_id VARCHAR(64) NOT NULL, case_id VARCHAR(64) NOT NULL,
       type VARCHAR(32) NOT NULL, claim TEXT NOT NULL, confidence FLOAT NOT NULL,
       evidence_event_ids JSON NOT NULL, reasoning TEXT, alternatives JSON,
       needs_human_review BOOLEAN NOT NULL, status VARCHAR(32) NOT NULL, created_at DATETIME NOT NULL,
       PRIMARY KEY (finding_id), FOREIGN KEY(case_id) REFERENCES cases (case_id))""",
    """CREATE TABLE events (event_id VARCHAR(64) NOT NULL, case_id VARCHAR(64) NOT NULL,
       evidence_id VARCHAR(64) NOT NULL, artifact_ref VARCHAR(512) NOT NULL, sha256 VARCHAR(64) NOT NULL,
       timestamp DATETIME NOT NULL, source VARCHAR(32) NOT NULL, device VARCHAR(255), actor VARCHAR(255),
       action VARCHAR(128) NOT NULL, object VARCHAR(512), ip VARCHAR(64), location JSON, raw JSON,
       PRIMARY KEY (event_id), FOREIGN KEY(case_id) REFERENCES cases (case_id),
       FOREIGN KEY(evidence_id) REFERENCES evidence (evidence_id))""",
    """CREATE TABLE custody_entries (id INTEGER NOT NULL, evidence_id VARCHAR(64) NOT NULL,
       actor VARCHAR(128) NOT NULL, action VARCHAR(128) NOT NULL, time DATETIME NOT NULL,
       sha256 VARCHAR(64) NOT NULL, prev_hash VARCHAR(64) NOT NULL, entry_hash VARCHAR(64) NOT NULL,
       PRIMARY KEY (id), FOREIGN KEY(evidence_id) REFERENCES evidence (evidence_id))""",
]

SHA = "a" * 64
T0 = datetime(2026, 10, 18, 2, 17, 0)
NEW_TABLES = {"analysis_run", "claim", "claim_edge", "hypothesis_eval", "source_coverage"}


@pytest.fixture
def legacy_engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    genesis = compute_entry_hash("0" * 64, "EVID-001", "Intake", "Acquired", format_custody_time(T0), SHA)
    second = compute_entry_hash(genesis, "EVID-001", "Examiner", "Sealed", format_custody_time(T0), SHA)
    with engine.begin() as conn:
        for ddl in PRE_T3_DDL:
            conn.execute(text(ddl))
        conn.execute(text("INSERT INTO cases VALUES ('CASE-OLD', 'Legacy', :t)"), {"t": T0})
        conn.execute(text(
            "INSERT INTO evidence VALUES ('EVID-001', 'CASE-OLD', 'log.csv', :sha, 10, :t, '/vault/log.csv')"
        ), {"sha": SHA, "t": T0})
        conn.execute(text(
            "INSERT INTO events (event_id, case_id, evidence_id, artifact_ref, sha256, timestamp, source, action) "
            "VALUES ('EV-1', 'CASE-OLD', 'EVID-001', 'log.csv#row=1', :sha, :t, 'log', 'login')"
        ), {"sha": SHA, "t": T0})
        conn.execute(text(
            "INSERT INTO custody_entries VALUES (1, 'EVID-001', 'Intake', 'Acquired', :t, :sha, :p, :h)"
        ), {"t": T0, "sha": SHA, "p": "0" * 64, "h": genesis})
        conn.execute(text(
            "INSERT INTO custody_entries VALUES (2, 'EVID-001', 'Examiner', 'Sealed', :t, :sha, :p, :h)"
        ), {"t": T0, "sha": SHA, "p": genesis, "h": second})
    yield engine
    engine.dispose()


def test_migrate_adds_columns_and_tables(legacy_engine):
    added = migrate(legacy_engine)
    assert set(added) == {
        "evidence.status", "evidence.verified_at",
        "events.parser_version", "events.tz_assumption", "events.family",
    }
    insp = inspect(legacy_engine)
    assert NEW_TABLES <= set(insp.get_table_names())
    assert {"status", "verified_at"} <= {c["name"] for c in insp.get_columns("evidence")}
    assert {"parser_version", "tz_assumption", "family"} <= {c["name"] for c in insp.get_columns("events")}


def test_migrate_preserves_rows_and_custody_chain(legacy_engine):
    migrate(legacy_engine)
    db = sessionmaker(bind=legacy_engine)()
    try:
        ev = db.get(Evidence, "EVID-001")
        assert ev.status == "ACTIVE"  # server default backfills existing rows
        assert ev.verified_at is None
        assert ev.sha256 == SHA and ev.stored_path == "/vault/log.csv"
        assert len(ev.custody_entries) == 2

        event = db.get(EventModel, "EV-1")
        assert event.action == "login"
        assert event.parser_version is None and event.family is None

        ok, msg = verify_custody_log(db, "EVID-001")
        assert ok, msg
    finally:
        db.close()


def test_migrate_is_idempotent(legacy_engine):
    assert migrate(legacy_engine)
    assert migrate(legacy_engine) == []
    assert migrate_mod.pending_columns(legacy_engine) == []


def test_init_db_runs_migration(legacy_engine):
    init_db(legacy_engine)
    assert "status" in {c["name"] for c in inspect(legacy_engine).get_columns("evidence")}


def test_fresh_database_needs_no_column_migration(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    assert migrate(engine) == []
    assert NEW_TABLES <= set(inspect(engine).get_table_names())
    engine.dispose()


def test_non_additive_column_is_refused(legacy_engine, monkeypatch):
    md = MetaData()
    Table("evidence", md, Column("evidence_id", String(64), primary_key=True),
          Column("must_have", Integer, nullable=False))  # NOT NULL, no server default
    monkeypatch.setattr(migrate_mod.Base, "metadata", md)
    with pytest.raises(MigrationError, match="must_have"):
        migrate_mod.pending_columns(legacy_engine)


def test_add_column_sql_renders_default_and_not_null(legacy_engine):
    status_col = Evidence.__table__.c.status
    sql = migrate_mod._add_column_sql(status_col, legacy_engine)
    assert sql.startswith("ALTER TABLE evidence ADD COLUMN status VARCHAR(16)")
    assert "DEFAULT 'ACTIVE'" in sql and sql.endswith("NOT NULL")
