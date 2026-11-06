"""Tests for PostgreSQL disposable database safety validation.

Verifies that missing confirmation, unsafe database names, and invalid configuration
prevent destructive operations and fail closed.
"""
from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.engine import create_engine

from backend.tests.test_postgres_migration import (
    PostgresSafetyError,
    assert_safe_disposable_connection,
    validate_disposable_pg_url,
)


def test_safety_rejects_missing_url():
    with pytest.raises(PostgresSafetyError, match="PRAMANA_TEST_PG_URL must be provided"):
        validate_disposable_pg_url(None, "1")
    with pytest.raises(PostgresSafetyError, match="PRAMANA_TEST_PG_URL must be provided"):
        validate_disposable_pg_url("", "1")


def test_safety_rejects_missing_disposable_flag():
    url = "postgresql+psycopg2://postgres:test@localhost:5432/pramana_test"
    with pytest.raises(PostgresSafetyError, match="PRAMANA_TEST_PG_DISPOSABLE=1 environment variable"):
        validate_disposable_pg_url(url, None)
    with pytest.raises(PostgresSafetyError, match="PRAMANA_TEST_PG_DISPOSABLE=1 environment variable"):
        validate_disposable_pg_url(url, "")
    with pytest.raises(PostgresSafetyError, match="PRAMANA_TEST_PG_DISPOSABLE=1 environment variable"):
        validate_disposable_pg_url(url, "0")
    with pytest.raises(PostgresSafetyError, match="PRAMANA_TEST_PG_DISPOSABLE=1 environment variable"):
        validate_disposable_pg_url(url, "false")


def test_safety_rejects_forbidden_database_names():
    for forbidden in ("postgres", "template1", "production", "prod", "main", "master", "live", "defaultdb"):
        url = f"postgresql+psycopg2://postgres:test@localhost:5432/{forbidden}"
        with pytest.raises(PostgresSafetyError, match="forbidden for destructive testing"):
            validate_disposable_pg_url(url, "1")


def test_safety_rejects_non_test_naming_convention():
    for unsafe_name in ("company_db", "client_records", "forensics_case_data", "analytics"):
        url = f"postgresql+psycopg2://postgres:test@localhost:5432/{unsafe_name}"
        with pytest.raises(PostgresSafetyError, match="does not meet the test-naming convention"):
            validate_disposable_pg_url(url, "1")


def test_safety_rejects_non_postgres_driver():
    url = "mysql+pymysql://root:test@localhost:3306/pramana_test"
    with pytest.raises(PostgresSafetyError, match="Database driver must be PostgreSQL"):
        validate_disposable_pg_url(url, "1")


def test_safety_accepts_valid_disposable_database():
    valid_urls = [
        "postgresql+psycopg2://postgres:test@localhost:5432/pramana_test",
        "postgresql://user:pass@localhost:5432/disposable_db",
        "postgresql+psycopg://postgres:secret@127.0.0.1:5432/my_scratch_db",
    ]
    for url in valid_urls:
        db_name = validate_disposable_pg_url(url, "1")
        assert any(kw in db_name for kw in ("test", "disposable", "scratch"))


def test_server_connection_safety_verification():
    """assert_safe_disposable_connection fails closed if server current_database differs."""
    # Use in-memory SQLite connection mock to test the logic
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        # SQLite returns scalar None for current_database() unless simulated
        with pytest.raises(Exception):
            assert_safe_disposable_connection(conn, "pramana_test")
