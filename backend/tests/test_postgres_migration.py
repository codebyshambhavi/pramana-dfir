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


@pytest.fixture
def non_utc_server(pg_engine):
    """Server default timezone set to Asia/Kolkata (UTC+05:30) for new sessions; reset afterwards."""
    import psycopg2
    with pg_engine.connect() as conn:
        dbname = conn.execute(text("SELECT current_database()")).scalar()
    with create_engine(PG_URL, isolation_level="AUTOCOMMIT").connect() as conn:
        conn.execute(text(f'ALTER DATABASE "{dbname}" SET timezone TO \'Asia/Kolkata\''))
    raw = psycopg2.connect(pg_engine.url.render_as_string(hide_password=False).replace("postgresql+psycopg2", "postgresql"))
    try:
        cur = raw.cursor()
        cur.execute("SHOW timezone")
        assert cur.fetchone()[0] == "Asia/Kolkata"  # a plain connection really is non-UTC
    finally:
        raw.close()
    yield
    with create_engine(PG_URL, isolation_level="AUTOCOMMIT").connect() as conn:
        conn.execute(text(f'ALTER DATABASE "{dbname}" RESET timezone'))


def test_pg_sessions_are_utc_even_on_non_utc_server(non_utc_server):
    engine = create_engine(PG_URL, pool_size=1, max_overflow=0)
    try:
        for _ in range(3):  # same pooled connection, reused after reset-on-return rollbacks
            with engine.connect() as conn:
                assert conn.execute(text("SHOW timezone")).scalar() == "UTC"
                conn.rollback()
    finally:
        engine.dispose()


def test_pg_custody_and_verify_on_non_utc_server(non_utc_server, tmp_path):
    from app.db.session import append_custody_record, verify_evidence
    import hashlib

    engine = create_engine(PG_URL)
    try:
        migrate(engine)
        stored = tmp_path / "artifact.bin"
        stored.write_bytes(b"pramana")
        sha = hashlib.sha256(b"pramana").hexdigest()
        db = sessionmaker(bind=engine)()
        db.execute(text("INSERT INTO evidence (evidence_id, case_id, filename, sha256, size_bytes, intake_time, "
                        "stored_path, status) VALUES ('EVID-TZ', 'CASE-PG', 'artifact.bin', :s, 7, now(), :p, "
                        "'ACTIVE')"), {"s": sha, "p": str(stored)})
        append_custody_record(db, "EVID-TZ", "Intake", "Acquired", sha)  # timezone-aware utc_now() inside
        db.commit()

        drift = db.execute(text("SELECT abs(extract(epoch FROM (now() AT TIME ZONE 'UTC') - time)) "
                                "FROM custody_entries WHERE evidence_id = 'EVID-TZ'")).scalar()
        assert drift < 120, f"custody time stored {drift}s away from real UTC"
        assert verify_custody_log(db, "EVID-TZ")[0]

        result = verify_evidence(db, "EVID-TZ")
        db.commit()
        assert (result["verify_state"], result["status"], result["custody_chain_valid"]) == ("MATCH", "ACTIVE", True)
        db.close()
    finally:
        engine.dispose()


def test_pg_t8_run_snapshot_immutability(pg_engine):
    """PostgreSQL triggers enforce write-once immutability on run_snapshots."""
    migrate(pg_engine)
    db = sessionmaker(bind=pg_engine)()
    try:
        run = create_analysis_run(
            db,
            "CASE-PG",
            engine_version="e@1",
            assumptions={"case_timezone": "UTC"},
            snapshot_data={"test": "initial_data"},
            template_hash="tmpl@1.0.0",
        )
        db.commit()

        # 1. Reject UPDATE of run_snapshots
        with pytest.raises(DBAPIError, match="PRAMANA: run_snapshots rows are write-once"):
            db.execute(text("UPDATE run_snapshots SET template_hash = 'tampered' WHERE run_id = :r"), {"r": run.run_id})
        db.rollback()

        # 2. Reject DELETE of run_snapshots
        with pytest.raises(DBAPIError, match="PRAMANA: run_snapshots rows are write-once"):
            db.execute(text("DELETE FROM run_snapshots WHERE run_id = :r"), {"r": run.run_id})
        db.rollback()

        # 3. Reject TRUNCATE of run_snapshots
        with pytest.raises(DBAPIError, match="PRAMANA: run_snapshots rows are write-once"):
            db.execute(text("TRUNCATE run_snapshots CASCADE"))
        db.rollback()
    finally:
        db.close()


def test_pg_t8_run_snapshot_sealed_run(pg_engine):
    """PostgreSQL trigger rejects inserting child snapshot records once parent run is sealed."""
    migrate(pg_engine)
    db = sessionmaker(bind=pg_engine)()
    try:
        run = create_analysis_run(
            db,
            "CASE-PG",
            engine_version="e@1",
            assumptions={"case_timezone": "UTC"},
        )
        db.commit()

        # Attempt late insertion of a snapshot for the sealed run
        with pytest.raises(DBAPIError, match="PRAMANA: run already exists; its records cannot be added later"):
            db.execute(
                text(
                    "INSERT INTO run_snapshots (run_id, case_id, template_hash, snapshot, created_at) "
                    "VALUES (:r, 'CASE-PG', 'late_hash', '{\"late\": true}', now())"
                ),
                {"r": run.run_id},
            )
        db.rollback()
    finally:
        db.close()


def test_pg_t8_transaction_atomicity_and_rollback(pg_engine):
    """Transaction rollback on failure leaves zero partial rows in PostgreSQL."""
    from app.db.claims import ClaimSpec, EdgeSpec, ClaimValidationError
    from app.db.models import AnalysisRun, Claim, RunSnapshot

    migrate(pg_engine)
    db = sessionmaker(bind=pg_engine)()
    try:
        initial_runs = db.query(AnalysisRun).count()
        initial_claims = db.query(Claim).count()
        initial_snaps = db.query(RunSnapshot).count()

        spec_valid = ClaimSpec(
            type="ACTOR_DEVICE_CONSISTENT",
            params={"actor": "mira", "device": "dev-01"},
            status="ASSERTED",
            grade="A",
            rule_id="RULE-1",
            rule_version="1.0",
            edges=[EdgeSpec(ref_kind="event", ref_id="EV-1", role="SUPPORTS")],
        )
        spec_invalid = ClaimSpec(
            type="ACTOR_DEVICE_CONSISTENT",
            params={"actor": "mira", "device": "dev-01"},
            status="ASSERTED",
            grade="A",
            rule_id="RULE-1",
            rule_version="1.0",
            edges=[EdgeSpec(ref_kind="event", ref_id="NON_EXISTENT_EV", role="SUPPORTS")],
        )

        with pytest.raises(ClaimValidationError):
            create_analysis_run(
                db,
                case_id="CASE-PG",
                engine_version="e@1",
                assumptions={"case_timezone": "UTC"},
                claims=[spec_valid, spec_invalid],
                snapshot_data={"partial": "fail"},
            )

        db.rollback()
        assert db.query(AnalysisRun).count() == initial_runs
        assert db.query(Claim).count() == initial_claims
        assert db.query(RunSnapshot).count() == initial_snaps
    finally:
        db.close()


def test_pg_t8_full_execution_and_reproducibility(pg_engine):
    """Full T7/T8 execution and independent verification against PostgreSQL."""
    from app.services.runs import execute_analysis_run, get_run_details, verify_run_reproducibility

    migrate(pg_engine)
    db = sessionmaker(bind=pg_engine)()
    try:
        run_res = execute_analysis_run(
            db,
            case_id="CASE-PG",
            engine_version="pramana-engine@1.0.0",
            assumptions={"case_timezone": "UTC"},
        )
        db.commit()

        run_id = run_res["run_id"]
        details = get_run_details(db, run_id, verify=True)
        assert details["snapshot_source"] == "database"
        assert details["snapshot_authoritative"] is True
        assert details["snapshot_status"] == "AUTHORITATIVE_DB"
        assert details["ranking_hash_verified"] is True
        assert details["verification"]["verified"] is True
        assert details["verification"]["historical_replay"]["verified"] is True
        assert details["verification"]["historical_replay"]["ranking_hash_match"] is True
        assert details["verification"]["historical_replay"]["snapshot_authoritative"] is True
    finally:
        db.close()

