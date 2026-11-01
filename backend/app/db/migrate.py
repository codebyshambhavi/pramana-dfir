"""Role 3 / T3: additive schema migration.

`Base.metadata.create_all` creates missing tables but never alters an existing
one. This module closes that gap without Alembic, under one rule: migrations
are ADDITIVE ONLY. It may create tables and add columns. It never drops,
renames or retypes anything and never rewrites existing rows (beyond the
server default a new NOT NULL column needs).

A model column can be added to an existing table only if it is nullable or has
a server default. Anything else raises, because adding it would need a data
decision that a migration must not make silently.

Idempotent: running it again on an up-to-date database changes nothing.
Works on SQLite and PostgreSQL.
"""
from __future__ import annotations

import logging

from sqlalchemy import Column, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.sql.elements import TextClause

from app.db.models import Base

logger = logging.getLogger("pramana.migrate")


class MigrationError(RuntimeError):
    """Raised when the database cannot be brought to the model schema additively."""


def _default_sql(column: Column, engine: Engine) -> str | None:
    default = column.server_default
    if default is None:
        return None
    arg = getattr(default, "arg", None)
    if isinstance(arg, TextClause):
        return arg.text
    if isinstance(arg, str):
        return "'" + arg.replace("'", "''") + "'"
    raise MigrationError(f"Unsupported server default on {column.table.name}.{column.name}: {default!r}")


def _add_column_sql(column: Column, engine: Engine) -> str:
    preparer = engine.dialect.identifier_preparer
    col_type = column.type.compile(dialect=engine.dialect)
    parts = [
        f"ALTER TABLE {preparer.format_table(column.table)}",
        f"ADD COLUMN {preparer.format_column(column)} {col_type}",
    ]
    default = _default_sql(column, engine)
    if default is not None:
        parts.append(f"DEFAULT {default}")
    if not column.nullable:
        parts.append("NOT NULL")
    return " ".join(parts)


def pending_columns(engine: Engine) -> list[Column]:
    """Model columns missing from tables that already exist in the database."""
    inspector = inspect(engine)
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


def migrate(engine: Engine) -> list[str]:
    """Create missing tables, then add missing columns. Returns 'table.column' names added."""
    Base.metadata.create_all(bind=engine)
    columns = pending_columns(engine)
    added: list[str] = []
    if not columns:
        return added
    with engine.begin() as conn:
        for column in columns:
            conn.execute(text(_add_column_sql(column, engine)))
            name = f"{column.table.name}.{column.name}"
            added.append(name)
            logger.info("Added column %s", name)
    return added
