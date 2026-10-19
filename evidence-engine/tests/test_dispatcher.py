"""Tests for the Role 1 evidence dispatcher."""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from parsers import parse_evidence


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_dispatches_browser_csv(tmp_path: Path):
    path = _write(
        tmp_path / "browser.csv",
        "timestamp,action,url,actor\n"
        "2026-01-01T02:30:00Z,visit,https://example.com,alice\n",
    )
    events = parse_evidence(str(path), "CASE-001")
    assert len(events) == 1
    assert events[0]["source"] == "browser"
    assert events[0]["evidence_id"] == "EVID-001"
    assert events[0]["sha256"]
    assert events[0]["event_id"].endswith(":EV-000001")


def test_dispatches_log_csv(tmp_path: Path):
    path = _write(
        tmp_path / "system.csv",
        "timestamp,action,actor,object\n"
        "2026-01-01T02:30:00Z,login,alice,/work\n",
    )
    events = parse_evidence(str(path), "CASE-001")
    assert len(events) == 1
    assert events[0]["source"] == "log"


def test_dispatches_chat_json(tmp_path: Path):
    path = tmp_path / "chat.json"
    path.write_text(
        json.dumps([{"timestamp": "2026-01-01T10:00:00Z", "action": "message", "actor": "alice"}]),
        encoding="utf-8",
    )
    events = parse_evidence(str(path), "CASE-001")
    assert len(events) == 1
    assert events[0]["source"] == "chat"
    assert events[0]["actor"] == "alice"


def test_dispatches_image(tmp_path: Path):
    from PIL import Image

    path = tmp_path / "photo.jpg"
    Image.new("RGB", (8, 8), "white").save(path, format="JPEG")
    events = parse_evidence(str(path), "CASE-001")
    assert len(events) == 1
    assert events[0]["source"] == "image"


def test_csv_with_url_is_browser_even_when_filename_looks_like_log(tmp_path: Path):
    path = _write(
        tmp_path / "system.log.csv",
        "timestamp,action,url\n"
        "2026-01-01T10:00:00Z,visit,https://example.com\n",
    )
    events = parse_evidence(str(path), "CASE-001")
    assert events[0]["source"] == "browser"


def test_unsupported_format_raises_clear_value_error(tmp_path: Path):
    path = _write(tmp_path / "evidence.txt", "hello")
    with pytest.raises(ValueError, match="Unsupported evidence format"):
        parse_evidence(str(path), "CASE-001")


def test_missing_file_raises_value_error(tmp_path: Path):
    with pytest.raises(ValueError, match="does not exist"):
        parse_evidence(str(tmp_path / "missing.json"), "CASE-001")


def test_empty_case_id_rejected(tmp_path: Path):
    path = _write(
        tmp_path / "log.csv",
        "timestamp,action\n2026-01-01T10:00:00Z,login\n",
    )
    with pytest.raises(ValueError, match="case_id"):
        parse_evidence(str(path), "")


def test_event_ids_do_not_collide_between_evidence_files(tmp_path: Path):
    p1 = _write(tmp_path / "one.csv", "timestamp,action\n2026-01-01T10:00:00Z,login\n")
    p2 = _write(tmp_path / "two.csv", "timestamp,action\n2026-01-01T10:01:00Z,login\n")
    e1 = parse_evidence(str(p1), "CASE-001")
    e2 = parse_evidence(str(p2), "CASE-001")
    assert e1[0]["event_id"] != e2[0]["event_id"]


def test_ambiguous_csv_is_rejected(tmp_path: Path):
    path = _write(tmp_path / "unknown.csv", "foo,bar\na,b\n")
    with pytest.raises(ValueError, match="Unsupported CSV evidence"):
        parse_evidence(str(path), "CASE-001")
