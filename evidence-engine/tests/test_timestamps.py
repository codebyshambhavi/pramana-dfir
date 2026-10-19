"""Tests for normalized parser timestamps and schema format validation."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from parsers import _load_event_validator, _validate_events, parse_evidence
from parsers.timestamps import normalize_timestamp


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-10-18T12:32:12+02:00", "2026-10-18T10:32:12Z"),
        ("2026-10-18T10:32:12", "2026-10-18T10:32:12Z"),
        ("2026-10-18T10:32:12Z", "2026-10-18T10:32:12Z"),
    ],
)
def test_normalize_timestamp(value: str, expected: str):
    assert normalize_timestamp(value) == expected


def test_parser_timestamps_normalize_to_utc(tmp_path: Path):
    samples = [
        (
            tmp_path / "browser.csv",
            "timestamp,action,url\n2026-10-18T12:32:12+02:00,visit,https://example.test\n",
        ),
        (
            tmp_path / "system.csv",
            "timestamp,action\n2026-10-18T12:32:12+02:00,login\n",
        ),
    ]

    for path, content in samples:
        path.write_text(content, encoding="utf-8")
        event = parse_evidence(str(path), "CASE-001")[0]
        assert event["timestamp"] == "2026-10-18T10:32:12Z"

    chat_path = tmp_path / "chat.json"
    chat_path.write_text(
        json.dumps([{"timestamp": "2026-10-18T12:32:12+02:00", "action": "message"}]),
        encoding="utf-8",
    )
    event = parse_evidence(str(chat_path), "CASE-001")[0]
    assert event["timestamp"] == "2026-10-18T10:32:12Z"


def test_parser_rejects_invalid_date_time(tmp_path: Path):
    path = tmp_path / "chat.json"
    path.write_text(
        json.dumps([{"timestamp": "not-a-date", "action": "message"}]),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid ISO 8601 timestamp"):
        parse_evidence(str(path), "CASE-001")


def test_dispatcher_checks_date_time_format():
    event = {
        "event_id": "EV-1",
        "case_id": "CASE-001",
        "evidence_id": "EVID-001",
        "artifact_ref": "chat.json#item=0",
        "sha256": "a" * 64,
        "timestamp": "not-a-date",
        "source": "chat",
        "action": "message",
        "raw": {},
    }
    with pytest.raises(ValueError, match="Parser produced schema-invalid Events"):
        _validate_events([event], _load_event_validator())