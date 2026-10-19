"""Pytest setup for Role 2 tests.

Makes the repository root importable so ``import intelligence`` works wherever
pytest is launched from. Role 2 tests never touch the backend, database or
network.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from intelligence.tests import fixtures  # noqa: E402


@pytest.fixture
def events() -> list[dict]:
    return fixtures.all_events()


@pytest.fixture
def known_ids(events) -> set[str]:
    return {e["event_id"] for e in events}
