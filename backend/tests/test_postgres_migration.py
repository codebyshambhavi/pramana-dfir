"""PostgreSQL migration and guard checks. Skipped unless PRAMANA_TEST_PG_URL points at a DISPOSABLE database
AND PRAMANA_TEST_PG_DISPOSABLE=1 is explicitly set.

    docker run --rm -d --name pramana-pg-test -e POSTGRES_PASSWORD=test -p 55432:5432 postgres:16-alpine
    psql -h localhost -p 55432 -U postgres -c "CREATE DATABASE pramana_test;"
    PRAMANA_TEST_PG_URL=postgresql+psycopg2://postgres:test@localhost:55432/pramana_test PRAMANA_TEST_PG_DISPOSABLE=1 pytest tests/test_postgres_migration.py

SAFETY REQUIREMENTS:
1. PRAMANA_TEST_PG_DISPOSABLE=1 must be set.
2. The database name in PRAMANA_TEST_PG_URL must contain 'test', 'disposable', or 'scratch'.
3. The database name must NOT be a system/production name (e.g. 'postgres', 'production', 'main').
4. The connected database identity is strictly verified on the server before dropping/recreating the public schema.
"""
from __future__ import annotations

import os
import threading
from datetime import datetime

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine, make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import sessionmaker

from app.db.migrate import migrate
from app.db.models import compute_entry_hash
from app.db.runs import create_analysis_run
from app.db.session import format_custody_time, verify_custody_log


class PostgresSafetyError(RuntimeError):
    """Raised when safety checks fail before executing destructive PostgreSQL operations."""


SAFE_DB_NAME_KEYWORDS = ("test", "disposable", "scratch")
FORBIDDEN_DB_NAMES = frozenset({
    "postgres",
    "template0",
    "template1",
    "prod",
    "production",
    "main",
    "master",
    "live",
    "defaultdb",
    "root",
    "admin",
})


def validate_disposable_pg_url(url: str | None, disposable_confirmation: str | None) -> str:
    """Validate that the PostgreSQL URL points to an explicitly confirmed disposable test database.

    Fails closed if any condition is not met. Returns the validated database name.
    """
    if not url:
        raise PostgresSafetyError("PRAMANA_TEST_PG_URL must be provided.")

    if not disposable_confirmation or disposable_confirmation.strip().lower() not in ("1", "true", "yes"):
        raise PostgresSafetyError(
            "Destructive PostgreSQL test operations require explicit confirmation via "
            "PRAMANA_TEST_PG_DISPOSABLE=1 environment variable."
        )

    try:
        parsed = make_url(url)
    except Exception as exc:
        raise PostgresSafetyError(f"Invalid database URL: {exc}") from exc

    if not parsed.drivername.startswith("postgresql"):
        raise PostgresSafetyError(f"Database driver must be PostgreSQL, got: {parsed.drivername}")

    db_name = parsed.database
    if not db_name:
        raise PostgresSafetyError("Database URL must explicitly specify a database name.")

    normalized_db = db_name.strip().lower()
    if normalized_db in FORBIDDEN_DB_NAMES:
        raise PostgresSafetyError(
            f"Database '{db_name}' is forbidden for destructive testing. Must not be a system or production name."
        )

    if not any(kw in normalized_db for kw in SAFE_DB_NAME_KEYWORDS):
        raise PostgresSafetyError(
            f"Database '{db_name}' does not meet the test-naming convention. "
            f"Name must contain one of: {', '.join(SAFE_DB_NAME_KEYWORDS)} (e.g. 'pramana_test')."
        )

    host = (parsed.host or "").lower()
    if any(p in host for p in ("prod", "production")) and not any(kw in host for kw in SAFE_DB_NAME_KEYWORDS):
        raise PostgresSafetyError(f"Host '{host}' appears to be a production target.")

    return db_name


def assert_safe_disposable_connection(conn: Connection, expected_db: str) -> None:
    """Verify live server identity and database name before performing destructive DDL."""
    actual_db = conn.execute(text("SELECT current_database()")).scalar()
    if not actual_db:
        raise PostgresSafetyError("Could not determine current database name from PostgreSQL server.")

    if actual_db.strip().lower() != expected_db.strip().lower():
        raise PostgresSafetyError(
            f"Server database mismatch: expected '{expected_db}', but connected to '{actual_db}'."
        )

    normalized_actual = actual_db.strip().lower()
    if normalized_actual in FORBIDDEN_DB_NAMES:
        raise PostgresSafetyError(f"Connected database '{actual_db}' is in forbidden database names.")

    if not any(kw in normalized_actual for kw in SAFE_DB_NAME_KEYWORDS):
        raise PostgresSafetyError(
            f"Connected database '{actual_db}' does not satisfy disposable test-database naming convention."
        )


def _should_skip_pg_tests() -> tuple[bool, str]:
    url = os.getenv("PRAMANA_TEST_PG_URL")
    disposable = os.getenv("PRAMANA_TEST_PG_DISPOSABLE")
    if not url:
        return True, "PRAMANA_TEST_PG_URL not set (needs disposable PostgreSQL >= 14)"
    if not disposable or disposable.strip().lower() not in ("1", "true", "yes"):
        return True, "PRAMANA_TEST_PG_DISPOSABLE=1 not set (safety requirement for destructive PostgreSQL tests)"
    try:
        validate_disposable_pg_url(url, disposable)
    except PostgresSafetyError as exc:
        return True, f"PostgreSQL safety validation failed: {exc}"
    return False, ""


PG_URL = os.getenv("PRAMANA_TEST_PG_URL")
_skip_pg, _skip_reason = _should_skip_pg_tests()
pytestmark = pytest.mark.skipif(_skip_pg, reason=_skip_reason)

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
    url = os.getenv("PRAMANA_TEST_PG_URL")
    disposable = os.getenv("PRAMANA_TEST_PG_DISPOSABLE")
    safe_db = validate_disposable_pg_url(url, disposable)

    engine = create_engine(url)
    with engine.begin() as conn:
        assert_safe_disposable_connection(conn, safe_db)
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

