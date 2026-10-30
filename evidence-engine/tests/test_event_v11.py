"""Event v1.1: canonical actions, chat GPS -> location, provenance fields."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ENGINE = Path(__file__).resolve().parents[1]
if str(ENGINE) not in sys.path:
    sys.path.insert(0, str(ENGINE))

from parsers import _load_event_validator, parse_evidence
from parsers.timestamps import normalize_timestamp_with_basis
from parsers.vocabulary import CANONICAL_ACTIONS, canonical_action


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


# ---- vocabulary -------------------------------------------------------------
@pytest.mark.parametrize(
    "raw, expected",
    [
        ("archive_created", "archive_create"),
        ("upload", "file_upload"),
        ("Upload", "file_upload"),
        ("  archive_created ", "archive_create"),
        ("archive_create", "archive_create"),
        ("file_upload", "file_upload"),
        ("login", "login"),                     # not a synonym: unchanged
        ("DNS query example.test", "DNS query example.test"),
    ],
)
def test_canonical_action(raw, expected):
    assert canonical_action(raw) == expected


def test_canonical_action_rejects_empty():
    for bad in ("", "   ", None):
        with pytest.raises(ValueError):
            canonical_action(bad)  # type: ignore[arg-type]


def test_canonical_set_is_small_and_explicit():
    assert CANONICAL_ACTIONS == {"archive_create", "file_upload"}


def test_csv_parsers_normalize_action_and_keep_original(tmp_path):
    log = _write(tmp_path / "sys.csv", "timestamp,action,object\n2026-10-18T19:41:00Z,archive_created,a.tar.gz\n")
    web = _write(tmp_path / "web.csv", "timestamp,action,url\n2026-10-18T19:44:00Z,upload,https://h.test/a.tar.gz\n")
    (log_ev,) = parse_evidence(str(log), "C1")
    (web_ev,) = parse_evidence(str(web), "C1")
    assert log_ev["action"] == "archive_create" and log_ev["raw"]["action"] == "archive_created"
    assert web_ev["action"] == "file_upload" and web_ev["raw"]["action"] == "upload"


def test_chat_parser_normalizes_action_and_keeps_original(tmp_path):
    chat = _write(tmp_path / "c.json", json.dumps([{"timestamp": "2026-10-18T19:44:00Z", "action": "upload"}]))
    (ev,) = parse_evidence(str(chat), "C1")
    assert ev["action"] == "file_upload" and ev["raw"]["action"] == "upload"


# ---- chat GPS -> Event.location --------------------------------------------
def _chat(tmp_path, item):
    return _write(tmp_path / "c.json", json.dumps([{"timestamp": "2026-10-18T02:23:00Z", "action": "location_sync", **item}]))


def test_device_gps_becomes_event_location(tmp_path):
    (ev,) = parse_evidence(str(_chat(tmp_path, {"device_gps": {"lat": 40.7128, "lon": -74.006}})), "C1")
    assert ev["location"] == {"lat": 40.7128, "lon": -74.006}
    assert ev["raw"]["device_gps"] == {"lat": 40.7128, "lon": -74.006}  # raw untouched
    _load_event_validator().validate(ev)


def test_ip_location_is_not_promoted_to_event_location(tmp_path):
    (ev,) = parse_evidence(str(_chat(tmp_path, {"ip_location": {"lat": 38.9, "lon": -77.0}})), "C1")
    assert "location" not in ev
    assert ev["raw"]["ip_location"] == {"lat": 38.9, "lon": -77.0}


def test_no_gps_means_no_location_key(tmp_path):
    (ev,) = parse_evidence(str(_chat(tmp_path, {})), "C1")
    assert "location" not in ev
    (ev,) = parse_evidence(str(_chat(tmp_path, {"device_gps": None})), "C1")
    assert "location" not in ev


@pytest.mark.parametrize(
    "bad",
    [
        "40.7,-74.0",                      # not an object
        {"lat": 40.7},                     # missing lon
        {"lat": "40.7", "lon": -74.0},     # string, not number
        {"lat": True, "lon": -74.0},       # bool is not a number
        {"lat": 91, "lon": 0},             # out of range
        {"lat": 0, "lon": -181},
    ],
)
def test_malformed_device_gps_is_an_error_not_silently_dropped(tmp_path, bad):
    with pytest.raises(ValueError, match="device_gps"):
        parse_evidence(str(_chat(tmp_path, {"device_gps": bad})), "C1")


# ---- Event v1.1 fields ------------------------------------------------------
def test_v11_fields_present_on_every_source_and_schema_valid():
    case = Path(__file__).resolve().parents[2] / "datasets" / "sample_case_001"
    expected_family = {
        "system_log.csv": "system_log",
        "browser_history.csv": "browser_history",
        "chat_export.json": "chat_export",
        "network_dns.pcap": "network_capture",
        "field_photo.jpg": "image_exif",
    }
    validator = _load_event_validator()
    for name, family in expected_family.items():
        events = parse_evidence(str(case / name), "CASE-001")
        assert events
        for ev in events:
            validator.validate(ev)
            assert ev["family"] == family
            assert ev["parser_version"].endswith("@1.1.0")
            assert ev["tz_assumption"]


def test_tz_assumption_values():
    assert normalize_timestamp_with_basis("2026-10-18T02:17:00Z") == ("2026-10-18T02:17:00Z", "explicit_offset")
    assert normalize_timestamp_with_basis("2026-10-18T07:47:00+05:30") == ("2026-10-18T02:17:00Z", "explicit_offset")
    assert normalize_timestamp_with_basis("2026-10-18T02:17:00") == ("2026-10-18T02:17:00Z", "assumed_utc")


def test_parsers_label_naive_vs_explicit_timestamps(tmp_path):
    naive = _write(tmp_path / "n.csv", "timestamp,action\n2026-10-18T02:17:00,login\n")
    zoned = _write(tmp_path / "z.csv", "timestamp,action\n2026-10-18T02:17:00+05:30,login\n")
    (n,) = parse_evidence(str(naive), "C1")
    (z,) = parse_evidence(str(zoned), "C1")
    assert n["tz_assumption"] == "assumed_utc"
    assert z["tz_assumption"] == "explicit_offset"
    assert z["timestamp"] == "2026-10-17T20:47:00Z"       # normalized to UTC ...
    assert z["raw"]["timestamp"] == "2026-10-18T02:17:00+05:30"  # ... raw text unchanged


def test_v10_event_is_still_a_valid_v11_event():
    """Additive bump: an Event with none of the new fields must still validate."""
    v10 = {
        "event_id": "EV-1", "case_id": "C", "evidence_id": "EVID-001", "artifact_ref": "x#row=1",
        "sha256": "a" * 64, "timestamp": "2026-10-18T02:17:00Z", "source": "log", "action": "login",
    }
    _load_event_validator().validate(v10)


def test_unknown_event_fields_are_still_rejected():
    from jsonschema import ValidationError

    bad = {
        "event_id": "EV-1", "case_id": "C", "evidence_id": "EVID-001", "artifact_ref": "x#row=1",
        "sha256": "a" * 64, "timestamp": "2026-10-18T02:17:00Z", "source": "log", "action": "login",
        "surprise": 1,
    }
    with pytest.raises(ValidationError):
        _load_event_validator().validate(bad)
