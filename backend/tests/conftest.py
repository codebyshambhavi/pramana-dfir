"""Test configuration and fixtures for Pramana backend."""
from __future__ import annotations

import os
import tempfile
from typing import Generator
import pytest

# Isolate tests from the working tree and from any real database. These MUST be
# set before ``app`` is imported: the engine URL and upload directory are read
# at import time. They are overridden unconditionally (never setdefault) so a
# developer's real DATABASE_URL / UPLOAD_DIR can never be touched by a test run.
_TEST_ROOT = tempfile.mkdtemp(prefix="pramana-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_ROOT}/app-startup.db"
os.environ["UPLOAD_DIR"] = os.path.join(_TEST_ROOT, "uploads")
# Time configuration must not leak in from the developer's shell either.
os.environ.pop("PRAMANA_INTEL_TIMEZONE", None)
os.environ.pop("PRAMANA_SOURCE_CLOCKS", None)
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.migrate import migrate
from app.db.models import Base
from app.db.session import get_db
from app.main import app

# Create in-memory SQLite database for isolated unit and integration testing
TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(autouse=True)
def setup_database() -> Generator[None, None, None]:
    """Create clean database tables before each test and drop them after."""
    # Same path as production startup: tables, columns, data steps and integrity triggers.
    migrate(test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    """Provide a database session connected to the test database."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Provide FastAPI TestClient wired to the isolated in-memory test database."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
