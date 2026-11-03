"""Role 3 / T3: additive, non-destructive schema migration.

`Base.metadata.create_all` creates missing tables but never alters an existing
one. `migrate()` closes that gap without Alembic. In ONE transaction it:

1. takes a PostgreSQL advisory lock (pg_advisory_xact_lock), so concurrently
   starting workers migrate one at a time. SQLite needs no lock: it allows a
   single writer, and every step below is idempotent;
2. refuses tables whose existing shape is incompatible with the models (an
   existing NOT NULL column without a default that the model does not know, e.g.
   analysis_run.evidence_snapshot from an earlier draft of T3). It raises and
   changes nothing: it never drops, renames or rewrites a table;
3. creates missing tables;
4. adds missing columns (only if nullable or server-defaulted);
5. runs each data step once, recorded in `schema_migrations`;
6. (re)installs the integrity triggers (app.db.db_guards).

Running it again on an up-to-date database changes nothing.
"""
from __future__ import annotations

import logging
from typing import Callable

from sqlalchemy import Column, inspect, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import TextClause

from app.db.db_guards import install_guards
from app.db.models import (
    EVIDENCE_ACTIVE,
    VERIFY_MATCH,
    Base,
    Evidence,
    SchemaMigration,
)

logger = logging.getLogger("pramana.migrate")

# Arbitrary constant key for pg_advisory_xact_lock ("PRMN").
PG_MIGRATION_LOCK_KEY = 0x50524D4E


class MigrationError(RuntimeError):
    """Raised when the database cannot be brought to the model schema additively."""


def _default_sql(column: Column) -> str | None:
    default = column.server_default
    if default is None:
        return None
    arg = getattr(default, "arg", None)
    if isinstance(arg, TextClause):
        return arg.text
    if isinstance(arg, str):
        return "'" + arg.replace("'", "''") + "'"
    raise MigrationError(f"Unsupported server default on {column.table.name}.{column.name}: {default!r}")


def _add_column_sql(column: Column, bind: Engine | Connection) -> str:
    dialect = bind.dialect
    preparer = dialect.identifier_preparer
    parts = [
        f"ALTER TABLE {preparer.format_table(column.table)}",
        f"ADD COLUMN {preparer.format_column(column)} {column.type.compile(dialect=dialect)}",
    ]
    default = _default_sql(column)
    if default is not None:
        parts.append(f"DEFAULT {default}")
    if not column.nullable:
        parts.append("NOT NULL")
    return " ".join(parts)


def incompatible_columns(bind: Engine | Connection) -> list[str]:
    """Existing required columns the models do not know ('table.column'). Inserts would fail on them."""
    inspector = inspect(bind)
    existing = set(inspector.get_table_names())
    problems = []
    for table in Base.metadata.sorted_tables:
        if table.name not in existing:
            continue
        for col in inspector.get_columns(table.name):
            if col["name"] in table.columns:
                continue
            if not col.get("nullable", True) and col.get("default") is None and not col.get("autoincrement"):
                problems.append(f"{table.name}.{col['name']}")
    return problems


def pending_columns(bind: Engine | Connection) -> list[Column]:
    """Model columns missing from tables that already exist in the database."""
    inspector = inspect(bind)
    existing_tables = set(inspector.get_table_names())
    missing: list[Column] = []
    for table in Base.metadata.sorted_tables:
        if table.name not in existing_tables:
            continue  # create_all creates it whole
        present = {c["name"] for c in inspector.get_columns(table.name)}
        for column in table.columns:
            if column.name in present:
                continue
            if column.primary_key:
                raise MigrationError(f"Primary key column {table.name}.{column.name} is missing; not migratable")
            if not column.nullable and column.server_default is None:
                raise MigrationError(
                    f"{table.name}.{column.name} is NOT NULL without a server default; "
                    "it cannot be added to an existing table additively"
                )
            missing.append(column)
    return missing


# ---------------------------------------------------------------- data steps

def _step_verified_status_to_verify_state(conn: Connection) -> int:
    """An earlier T4 draft stored status VERIFIED. H″ allows only ACTIVE/QUARANTINED/REMOVED:
    VERIFIED becomes ACTIVE with verify_state MATCH, and each change gets a custody entry."""
    from app.db.session import append_custody_record  # local import: session imports this module

    ids = [r[0] for r in conn.execute(text("SELECT evidence_id FROM evidence WHERE status = 'VERIFIED'"))]
    if not ids:
        return 0
    db = Session(bind=conn)
    try:
        for evidence_id in ids:
            evidence = db.get(Evidence, evidence_id)
            evidence.status = EVIDENCE_ACTIVE
            if evidence.verify_state is None:
                evidence.verify_state = VERIFY_MATCH
            append_custody_record(
                db,
                evidence_id=evidence_id,
                actor="Schema migration",
                action="Schema migration: status VERIFIED -> ACTIVE, verify_state MATCH",
                sha256=evidence.sha256,
            )
        db.flush()
    finally:
        db.close()
    return len(ids)


DATA_STEPS: list[tuple[str, Callable[[Connection], int]]] = [
    ("t3-001-evidence-verified-status", _step_verified_status_to_verify_state),
]


def _run_data_steps(conn: Connection) -> list[str]:
    done = {r[0] for r in conn.execute(text("SELECT version FROM schema_migrations"))}
    applied = []
    for version, step in DATA_STEPS:
        if version in done:
            continue
        changed = step(conn)
        conn.execute(SchemaMigration.__table__.insert().values(version=version))
        applied.append(version)
        logger.info("Applied data step %s (%d rows)", version, changed)
    return applied


# ---------------------------------------------------------------- entry point

def migrate(engine: Engine) -> list[str]:
    """Bring the database to the model schema. Returns 'table.column' names added."""
    with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            conn.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": PG_MIGRATION_LOCK_KEY})

        problems = incompatible_columns(conn)
        if problems:
            raise MigrationError(
                "Existing tables have required columns the current models do not know: "
                + ", ".join(problems)
                + ". They come from an incompatible earlier schema; nothing was changed. "
                "Migrate or archive those tables manually (no automatic drop)."
            )

        Base.metadata.create_all(bind=conn)

        added: list[str] = []
        for column in pending_columns(conn):
            conn.execute(text(_add_column_sql(column, conn)))
            added.append(f"{column.table.name}.{column.name}")
            logger.info("Added column %s.%s", column.table.name, column.name)

        _run_data_steps(conn)
        install_guards(conn)
    return added
