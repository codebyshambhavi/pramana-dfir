"""T3: additive, non-destructive migration (pre-T3 schema, earlier T3/T4 drafts, idempotence, guards)."""
from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, inspect, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from app.db import migrate as migrate_mod
from app.db.migrate import MigrationError, migrate
from app.db.models import CustodyEntry, EventModel, Evidence, compute_entry_hash
from app.db.session import format_custody_time, init_db, verify_custody_log

# Exact DDL of the tables deployed before T3 (from a database created by the pre-T3 models).
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

# The analysis_run table from the first T3 draft (commit 548af27), before the H″ correction.
DRAFT_T3_ANALYSIS_RUN = """CREATE TABLE analysis_run (run_id VARCHAR(64) NOT NULL, case_id VARCHAR(64) NOT NULL,
    status VARCHAR(16) DEFAULT 'RUNNING' NOT NULL, created_at DATETIME NOT NULL, completed_at DATETIME,
    engine_version VARCHAR(64), config JSON, evidence_snapshot JSON NOT NULL, input_digest VARCHAR(64) NOT NULL,
    error TEXT, PRIMARY KEY (run_id), FOREIGN KEY(case_id) REFERENCES cases (case_id))"""

SHA = "a" * 64
T0 = datetime(2026, 10, 18, 2, 17, 0)
NEW_TABLES = {"analysis_run", "claim", "claim_edge", "hypothesis_eval", "source_coverage", "schema_migrations"}


def _build_pre_t3(engine) -> None:
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
        conn.execute(text("INSERT INTO custody_entries VALUES (1, 'EVID-001', 'Intake', 'Acquired', :t, :sha, :p, :h)"),
                     {"t": T0, "sha": SHA, "p": "0" * 64, "h": genesis})
        conn.execute(text("INSERT INTO custody_entries VALUES (2, 'EVID-001', 'Examiner', 'Sealed', :t, :sha, :p, :h)"),
                     {"t": T0, "sha": SHA, "p": genesis, "h": second})


@pytest.fixture
def legacy_engine(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    _build_pre_t3(engine)
    yield engine
    engine.dispose()


def _tables(engine) -> set[str]:
    return set(inspect(engine).get_table_names())


def _triggers(engine) -> set[str]:
    with engine.connect() as conn:
        return {r[0] for r in conn.execute(text("SELECT name FROM sqlite_master WHERE type = 'trigger'"))}


# --- pre-T3 (deployed) schema -------------------------------------------------

def test_migrate_pre_t3_adds_columns_tables_and_guards(legacy_engine):
    added = migrate(legacy_engine)
    assert set(added) == {
        "evidence.status", "evidence.verified_at", "evidence.verify_state",
        "events.parser_version", "events.tz_assumption", "events.family",
    }
    assert NEW_TABLES <= _tables(legacy_engine)
    assert {"trg_evidence_no_delete", "trg_custody_no_delete", "trg_analysis_run_validate",
            "trg_claim_sealed_run"} <= _triggers(legacy_engine)


def test_migrate_preserves_rows_and_custody_chain(legacy_engine):
    migrate(legacy_engine)
    db = sessionmaker(bind=legacy_engine)()
    try:
        ev = db.get(Evidence, "EVID-001")
        assert (ev.status, ev.verify_state, ev.verified_at) == ("ACTIVE", None, None)
        assert ev.sha256 == SHA and ev.stored_path == "/vault/log.csv"
        assert len(ev.custody_entries) == 2
        event = db.get(EventModel, "EV-1")
        assert event.action == "login" and event.parser_version is None
        ok, msg = verify_custody_log(db, "EVID-001")
        assert ok, msg
    finally:
        db.close()


def test_migrated_database_enforces_guards(legacy_engine):
    migrate(legacy_engine)
    with legacy_engine.connect() as conn:
        assert conn.execute(text("PRAGMA foreign_keys")).scalar() == 1
        with pytest.raises(DBAPIError, match="PRAMANA"):
            conn.execute(text("DELETE FROM evidence WHERE evidence_id = 'EVID-001'"))
        conn.rollback()
        with pytest.raises(DBAPIError, match="PRAMANA"):
            conn.execute(text("UPDATE evidence SET sha256 = 'b' WHERE evidence_id = 'EVID-001'"))


def test_migrate_is_idempotent(legacy_engine):
    assert migrate(legacy_engine)
    triggers = _triggers(legacy_engine)
    assert migrate(legacy_engine) == []
    assert migrate_mod.pending_columns(legacy_engine) == []
    assert _triggers(legacy_engine) == triggers
    with legacy_engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM custody_entries")).scalar() == 2
        assert conn.execute(text("SELECT COUNT(*) FROM schema_migrations")).scalar() == len(migrate_mod.DATA_STEPS)


def test_init_db_runs_migration(legacy_engine):
    init_db(legacy_engine)
    assert "verify_state" in {c["name"] for c in inspect(legacy_engine).get_columns("evidence")}


def test_fresh_empty_database(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    assert migrate(engine) == []
    assert NEW_TABLES <= _tables(engine)
    assert "trg_evidence_no_delete" in _triggers(engine)
    engine.dispose()


# --- earlier T4 draft: status VERIFIED ----------------------------------------

def test_verified_status_becomes_active_match_with_custody(legacy_engine):
    with legacy_engine.begin() as conn:  # state left by the first T4 draft
        conn.execute(text("ALTER TABLE evidence ADD COLUMN status VARCHAR(16) DEFAULT 'ACTIVE' NOT NULL"))
        conn.execute(text("ALTER TABLE evidence ADD COLUMN verified_at DATETIME"))
        conn.execute(text("UPDATE evidence SET status = 'VERIFIED', verified_at = :t"), {"t": T0})

    migrate(legacy_engine)
    db = sessionmaker(bind=legacy_engine)()
    try:
        ev = db.get(Evidence, "EVID-001")
        assert (ev.status, ev.verify_state) == ("ACTIVE", "MATCH")
        assert ev.verified_at is not None
        entries = db.query(CustodyEntry).filter_by(evidence_id="EVID-001").order_by(CustodyEntry.id).all()
        assert len(entries) == 3 and "VERIFIED -> ACTIVE" in entries[-1].action
        assert verify_custody_log(db, "EVID-001")[0]
    finally:
        db.close()

    migrate(legacy_engine)  # step recorded: no second custody entry
    with legacy_engine.connect() as conn:
        assert conn.execute(text("SELECT COUNT(*) FROM custody_entries")).scalar() == 3


# --- earlier T3 draft: incompatible run tables --------------------------------

def test_draft_t3_tables_are_refused_and_left_untouched(legacy_engine):
    with legacy_engine.begin() as conn:
        conn.execute(text(DRAFT_T3_ANALYSIS_RUN))
    before = _tables(legacy_engine)

    with pytest.raises(MigrationError, match="analysis_run.evidence_snapshot"):
        migrate(legacy_engine)

    assert _tables(legacy_engine) == before  # nothing created
    cols = {c["name"] for c in inspect(legacy_engine).get_columns("analysis_run")}
    assert "evidence_snapshot" in cols  # nothing dropped or rewritten
    assert "verify_state" not in {c["name"] for c in inspect(legacy_engine).get_columns("evidence")}


# --- helpers ------------------------------------------------------------------

def test_non_additive_column_is_refused(legacy_engine, monkeypatch):
    md = MetaData()
    Table("evidence", md, Column("evidence_id", String(64), primary_key=True),
          Column("must_have", Integer, nullable=False))  # NOT NULL, no server default
    monkeypatch.setattr(migrate_mod.Base, "metadata", md)
    with pytest.raises(MigrationError, match="must_have"):
        migrate_mod.pending_columns(legacy_engine)


def test_add_column_sql_renders_for_sqlite_and_postgres(legacy_engine):
    from sqlalchemy import create_mock_engine
    status_col = Evidence.__table__.c.status
    assert migrate_mod._add_column_sql(status_col, legacy_engine) == \
        "ALTER TABLE evidence ADD COLUMN status VARCHAR(16) DEFAULT 'ACTIVE' NOT NULL"
    pg = create_mock_engine("postgresql+psycopg2://", lambda *a, **k: None)
    assert migrate_mod._add_column_sql(Evidence.__table__.c.verified_at, pg) == \
        "ALTER TABLE evidence ADD COLUMN verified_at TIMESTAMP WITHOUT TIME ZONE"
