"""Role 3 / T3+T4: database-level integrity guards (SQLite and PostgreSQL >= 14).

What the database itself enforces (installed by app.db.migrate on every startup):

evidence
  - no DELETE (and no TRUNCATE on PostgreSQL)
  - sha256 (the intake hash) cannot change
  - status must be ACTIVE / QUARANTINED / REMOVED; verify_state NULL or a known value
custody_entries
  - no DELETE / TRUNCATE. UPDATE stays possible on purpose: tampering must remain
    possible to simulate and is detected by the hash chain (verify_custody_log).
analysis_run, claim, claim_edge, hypothesis_eval, source_coverage
  - no UPDATE, no DELETE, no TRUNCATE
  - a child row (claim, claim_edge, stubs) cannot be inserted once its run row exists
  - when the run row is inserted (always last), the database validates the whole run:
    parent run in the same case; every manifest entry is ACTIVE evidence of the case
    with the same intake SHA-256; every claim has the run's case_id and
    assumptions_hash; every claim edge targets a claim of the same run; every event
    edge targets an event of the case whose evidence is in the manifest.

What it does NOT enforce:
  - A trigger cannot tell which transaction created a row. The write-once rule is
    "no child after the run row exists". On PostgreSQL there is one residual race: a
    concurrent transaction that already knows an uncommitted run's random run_id
    could insert a child before that run row is visible to it. SQLite cannot hit
    this because it allows a single writer at a time.
  - Raw SQL that drops triggers, or a superuser disabling them, is out of scope.

SQLite foreign keys are off by default; every SQLite connection gets
PRAGMA foreign_keys=ON here (needed for the deferred run foreign keys).
Every PostgreSQL connection gets SET TIME ZONE 'UTC' (see _connection_defaults).
"""
from __future__ import annotations

import sqlite3

from sqlalchemy import event
from sqlalchemy.engine import Connection, Engine

from app.db.models import EVIDENCE_STATUSES, VERIFY_STATES

RUN_TABLES = ("analysis_run", "claim", "claim_edge", "hypothesis_eval", "source_coverage", "run_snapshots")
RUN_CHILD_TABLES = ("claim", "claim_edge", "hypothesis_eval", "source_coverage", "run_snapshots")


@event.listens_for(Engine, "connect")
def _connection_defaults(dbapi_connection, connection_record) -> None:
    """Per-connection settings every Pramana connection needs.

    SQLite: enforce foreign keys (off by default).
    PostgreSQL: session timezone UTC. Timestamps are stored in TIMESTAMP WITHOUT
    TIME ZONE columns; a timezone-aware value is converted to the *session*
    timezone before the offset is dropped, so a non-UTC server would store
    shifted times and every custody hash (computed over the UTC time) would
    fail re-verification.
    """
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    elif type(dbapi_connection).__module__.split(".")[0] in ("psycopg2", "psycopg"):
        cursor = dbapi_connection.cursor()
        cursor.execute("SET TIME ZONE 'UTC'")
        cursor.close()
        dbapi_connection.commit()  # keep the setting past the pool's reset-on-return rollback


def _in_list(values: tuple[str, ...]) -> str:
    return "(" + ", ".join(f"'{v}'" for v in values) + ")"


_STATUS_BAD = (
    f"NEW.status NOT IN {_in_list(EVIDENCE_STATUSES)} "
    f"OR (NEW.verify_state IS NOT NULL AND NEW.verify_state NOT IN {_in_list(VERIFY_STATES)})"
)


# ---------------------------------------------------------------- SQLite

def _sqlite_statements() -> list[tuple[str, str]]:
    """(trigger name, CREATE TRIGGER sql)."""
    def abort(msg: str) -> str:
        return f"SELECT RAISE(ABORT, 'PRAMANA: {msg}');"

    t: list[tuple[str, str]] = [
        ("trg_evidence_no_delete",
         f"CREATE TRIGGER trg_evidence_no_delete BEFORE DELETE ON evidence BEGIN "
         f"{abort('evidence rows are never deleted')} END"),
        ("trg_evidence_sha256_immutable",
         "CREATE TRIGGER trg_evidence_sha256_immutable BEFORE UPDATE OF sha256 ON evidence "
         f"WHEN NEW.sha256 IS NOT OLD.sha256 BEGIN {abort('evidence.sha256 is the immutable intake hash')} END"),
        ("trg_evidence_status_insert",
         f"CREATE TRIGGER trg_evidence_status_insert BEFORE INSERT ON evidence WHEN {_STATUS_BAD} "
         f"BEGIN {abort('invalid evidence status or verify_state')} END"),
        ("trg_evidence_status_update",
         f"CREATE TRIGGER trg_evidence_status_update BEFORE UPDATE OF status, verify_state ON evidence "
         f"WHEN {_STATUS_BAD} BEGIN {abort('invalid evidence status or verify_state')} END"),
        ("trg_custody_no_delete",
         f"CREATE TRIGGER trg_custody_no_delete BEFORE DELETE ON custody_entries BEGIN "
         f"{abort('custody entries are never deleted')} END"),
    ]
    for table in RUN_TABLES:
        t.append((f"trg_{table}_no_update",
                  f"CREATE TRIGGER trg_{table}_no_update BEFORE UPDATE ON {table} BEGIN "
                  f"{abort(table + ' rows are write-once')} END"))
        t.append((f"trg_{table}_no_delete",
                  f"CREATE TRIGGER trg_{table}_no_delete BEFORE DELETE ON {table} BEGIN "
                  f"{abort(table + ' rows are write-once')} END"))
    for table in RUN_CHILD_TABLES:
        t.append((f"trg_{table}_sealed_run",
                  f"CREATE TRIGGER trg_{table}_sealed_run BEFORE INSERT ON {table} "
                  "WHEN EXISTS (SELECT 1 FROM analysis_run r WHERE r.run_id = NEW.run_id) BEGIN "
                  f"{abort('run already exists; its records cannot be added later')} END"))
    t.append(("trg_analysis_run_validate", """
CREATE TRIGGER trg_analysis_run_validate AFTER INSERT ON analysis_run BEGIN
  SELECT RAISE(ABORT, 'PRAMANA: parent run must exist in the same case')
   WHERE NEW.parent_run_id IS NOT NULL AND NOT EXISTS (
     SELECT 1 FROM analysis_run p WHERE p.run_id = NEW.parent_run_id AND p.case_id = NEW.case_id);
  SELECT RAISE(ABORT, 'PRAMANA: manifest evidence must be ACTIVE evidence of the case with its intake SHA-256')
   WHERE EXISTS (
     SELECT 1 FROM json_each(NEW.manifest, '$.evidence') m WHERE NOT EXISTS (
       SELECT 1 FROM evidence e
        WHERE e.evidence_id = json_extract(m.value, '$.evidence_id') AND e.case_id = NEW.case_id
          AND e.sha256 = json_extract(m.value, '$.sha256') AND e.status = 'ACTIVE'));
  SELECT RAISE(ABORT, 'PRAMANA: claims must share the run case_id and assumptions_hash')
   WHERE EXISTS (
     SELECT 1 FROM claim c WHERE c.run_id = NEW.run_id
        AND (c.case_id <> NEW.case_id OR c.assumptions_hash <> NEW.assumptions_hash));
  SELECT RAISE(ABORT, 'PRAMANA: claim edge must target a claim of the same run')
   WHERE EXISTS (
     SELECT 1 FROM claim_edge g WHERE g.run_id = NEW.run_id AND g.ref_kind = 'claim' AND NOT EXISTS (
       SELECT 1 FROM claim c WHERE c.run_id = NEW.run_id AND c.claim_id = g.ref_id));
  SELECT RAISE(ABORT, 'PRAMANA: event edge must target an event of manifest evidence')
   WHERE EXISTS (
     SELECT 1 FROM claim_edge g WHERE g.run_id = NEW.run_id AND g.ref_kind = 'event' AND NOT EXISTS (
       SELECT 1 FROM events ev, json_each(NEW.manifest, '$.evidence') m
        WHERE ev.event_id = g.ref_id AND ev.case_id = NEW.case_id
          AND ev.evidence_id = json_extract(m.value, '$.evidence_id')));
END"""))
    return t


# ------------------------------------------------------------ PostgreSQL

_PG_FUNCTIONS = [
    """
CREATE OR REPLACE FUNCTION pramana_reject() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'PRAMANA: %', TG_ARGV[0] USING ERRCODE = 'integrity_constraint_violation';
END $$""",
    """
CREATE OR REPLACE FUNCTION pramana_sealed_run() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM analysis_run r WHERE r.run_id = NEW.run_id) THEN
    RAISE EXCEPTION 'PRAMANA: run already exists; its records cannot be added later'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END $$""",
    """
CREATE OR REPLACE FUNCTION pramana_validate_run() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.parent_run_id IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM analysis_run p WHERE p.run_id = NEW.parent_run_id AND p.case_id = NEW.case_id) THEN
    RAISE EXCEPTION 'PRAMANA: parent run must exist in the same case' USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF EXISTS (
       SELECT 1 FROM json_array_elements(NEW.manifest -> 'evidence') m WHERE NOT EXISTS (
         SELECT 1 FROM evidence e
          WHERE e.evidence_id = m ->> 'evidence_id' AND e.case_id = NEW.case_id
            AND e.sha256 = m ->> 'sha256' AND e.status = 'ACTIVE')) THEN
    RAISE EXCEPTION 'PRAMANA: manifest evidence must be ACTIVE evidence of the case with its intake SHA-256'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF EXISTS (
       SELECT 1 FROM claim c WHERE c.run_id = NEW.run_id
          AND (c.case_id <> NEW.case_id OR c.assumptions_hash <> NEW.assumptions_hash)) THEN
    RAISE EXCEPTION 'PRAMANA: claims must share the run case_id and assumptions_hash'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF EXISTS (
       SELECT 1 FROM claim_edge g WHERE g.run_id = NEW.run_id AND g.ref_kind = 'claim' AND NOT EXISTS (
         SELECT 1 FROM claim c WHERE c.run_id = NEW.run_id AND c.claim_id = g.ref_id)) THEN
    RAISE EXCEPTION 'PRAMANA: claim edge must target a claim of the same run'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  IF EXISTS (
       SELECT 1 FROM claim_edge g WHERE g.run_id = NEW.run_id AND g.ref_kind = 'event' AND NOT EXISTS (
         SELECT 1 FROM events ev, json_array_elements(NEW.manifest -> 'evidence') m
          WHERE ev.event_id = g.ref_id AND ev.case_id = NEW.case_id
            AND ev.evidence_id = m ->> 'evidence_id')) THEN
    RAISE EXCEPTION 'PRAMANA: event edge must target an event of manifest evidence'
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NULL;
END $$""",
]


def _pg_triggers() -> list[str]:
    def reject(msg: str) -> str:
        return f"EXECUTE FUNCTION pramana_reject('{msg}')"

    t = [
        f"CREATE OR REPLACE TRIGGER trg_evidence_no_delete BEFORE DELETE ON evidence "
        f"FOR EACH ROW {reject('evidence rows are never deleted')}",
        f"CREATE OR REPLACE TRIGGER trg_evidence_no_truncate BEFORE TRUNCATE ON evidence "
        f"FOR EACH STATEMENT {reject('evidence rows are never deleted')}",
        "CREATE OR REPLACE TRIGGER trg_evidence_sha256_immutable BEFORE UPDATE OF sha256 ON evidence "
        "FOR EACH ROW WHEN (NEW.sha256 IS DISTINCT FROM OLD.sha256) "
        f"{reject('evidence.sha256 is the immutable intake hash')}",
        f"CREATE OR REPLACE TRIGGER trg_evidence_status BEFORE INSERT OR UPDATE ON evidence "
        f"FOR EACH ROW WHEN ({_STATUS_BAD}) {reject('invalid evidence status or verify_state')}",
        f"CREATE OR REPLACE TRIGGER trg_custody_no_delete BEFORE DELETE ON custody_entries "
        f"FOR EACH ROW {reject('custody entries are never deleted')}",
        f"CREATE OR REPLACE TRIGGER trg_custody_no_truncate BEFORE TRUNCATE ON custody_entries "
        f"FOR EACH STATEMENT {reject('custody entries are never deleted')}",
    ]
    for table in RUN_TABLES:
        t.append(f"CREATE OR REPLACE TRIGGER trg_{table}_no_change BEFORE UPDATE OR DELETE ON {table} "
                 f"FOR EACH ROW {reject(table + ' rows are write-once')}")
        t.append(f"CREATE OR REPLACE TRIGGER trg_{table}_no_truncate BEFORE TRUNCATE ON {table} "
                 f"FOR EACH STATEMENT {reject(table + ' rows are write-once')}")
    for table in RUN_CHILD_TABLES:
        t.append(f"CREATE OR REPLACE TRIGGER trg_{table}_sealed_run BEFORE INSERT ON {table} "
                 "FOR EACH ROW EXECUTE FUNCTION pramana_sealed_run()")
    t.append("CREATE OR REPLACE TRIGGER trg_analysis_run_validate AFTER INSERT ON analysis_run "
             "FOR EACH ROW EXECUTE FUNCTION pramana_validate_run()")
    return t


def install_guards(conn: Connection) -> list[str]:
    """(Re)create all integrity triggers on this connection. Idempotent. Returns trigger names."""
    dialect = conn.dialect.name
    # Raw DBAPI cursor, no parameters: SQL text such as RAISE '...%' must not be
    # interpreted as bind-parameter syntax. Runs inside the caller's transaction.
    cursor = conn.connection.cursor()
    try:
        if dialect == "sqlite":
            names = []
            for name, sql in _sqlite_statements():
                cursor.execute(f"DROP TRIGGER IF EXISTS {name}")
                cursor.execute(sql)
                names.append(name)
            return names
        if dialect == "postgresql":
            version = conn.dialect.server_version_info or (0,)
            if version < (14,):
                raise RuntimeError("PostgreSQL >= 14 is required for CREATE OR REPLACE TRIGGER")
            for sql in _PG_FUNCTIONS:
                cursor.execute(sql)
            names = []
            for sql in _pg_triggers():
                cursor.execute(sql)
                names.append(sql.split()[4])
            return names
    finally:
        cursor.close()
    raise RuntimeError(f"Unsupported database dialect for integrity guards: {dialect}")
