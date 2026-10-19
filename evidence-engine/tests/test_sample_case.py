"""End-to-end checks for the deterministic synthetic sample case."""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENGINE = ROOT / "evidence-engine"
CASE_DIR = ROOT / "datasets" / "sample_case_001"
if str(ENGINE) not in sys.path:
    sys.path.insert(0, str(ENGINE))

from parsers import _load_event_validator, parse_evidence


def test_sample_case_events_are_valid_and_contain_three_planted_items():
    validator = _load_event_validator()
    evidence_paths = sorted(
        path
        for path in CASE_DIR.iterdir()
        if path.suffix.lower() in {".json", ".csv", ".pcap", ".jpg"}
    )
    assert {path.name for path in evidence_paths} == {
        "browser_history.csv",
        "chat_export.json",
        "field_photo.jpg",
        "network_dns.pcap",
        "reference_photo.jpg",
        "system_log.csv",
    }

    events_by_file = {
        path.name: parse_evidence(str(path), "CASE-001")
        for path in evidence_paths
    }
    events = [event for file_events in events_by_file.values() for event in file_events]
    assert events
    for event in events:
        validator.validate(event)
        json.dumps(event)
        assert event["evidence_id"] == "EVID-001"
        assert len(event["sha256"]) == 64

    login = next(event for event in events_by_file["system_log.csv"] if event["action"] == "login")
    assert login["timestamp"] == "2026-10-18T02:17:00Z"
    assert login["actor"] == "mira.chen"
    assert login["artifact_ref"].endswith("#row=1")

    archive_created = next(
        event for event in events_by_file["system_log.csv"]
        if event["action"] == "archive_created"
    )
    uploaded = next(
        event for event in events_by_file["browser_history.csv"]
        if event["action"] == "upload"
    )
    assert archive_created["object"] == uploaded["raw"]["url"].rsplit("/", 1)[-1]
    assert archive_created["actor"] == uploaded["actor"] == "mira.chen"
    assert archive_created["device"] == uploaded["device"] == "field-laptop-07"
    created_at = datetime.fromisoformat(archive_created["timestamp"].replace("Z", "+00:00"))
    uploaded_at = datetime.fromisoformat(uploaded["timestamp"].replace("Z", "+00:00"))
    assert (uploaded_at - created_at).total_seconds() == 180
    assert archive_created["artifact_ref"].endswith("#row=2")
    assert uploaded["artifact_ref"].endswith("#row=1")

    location_context = events_by_file["chat_export.json"][0]
    photo = events_by_file["field_photo.jpg"][0]
    device_gps = location_context["raw"]["device_gps"]
    ip_location = location_context["raw"]["ip_location"]
    exif_location = photo["location"]
    assert location_context["actor"] == "mira.chen"
    assert location_context["device"] == "field-phone-07"
    assert photo["device"] == "Northstar Mobile FieldPhone 7"
    assert photo["raw"]["exif"]["DateTimeOriginal"] == "2026:10:18 02:24:00"
    assert photo["raw"]["exif"]["Model"] == "FieldPhone 7"
    assert location_context["ip"] == "203.0.113.42"
    assert exif_location != device_gps
    assert exif_location != ip_location
    assert device_gps != ip_location
    assert photo["raw"]["perceptual_hash"]

    dns_events = events_by_file["network_dns.pcap"]
    assert any(event["action"] == "DNS query vault.example.test" for event in dns_events)
    dns_response = next(event for event in dns_events if event["action"] == "DNS response vault.example.test")
    assert dns_response["ip"] == "203.0.113.80"

    ground_truth = (CASE_DIR / "GROUND_TRUTH.md").read_text(encoding="utf-8")
    for planted_event in (login, archive_created, uploaded, location_context, photo):
        assert planted_event["event_id"] in ground_truth
        assert planted_event["artifact_ref"] in ground_truth