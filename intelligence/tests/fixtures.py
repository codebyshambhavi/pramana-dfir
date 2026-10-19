"""Synthetic Event fixtures for Role 2 tests.

Only fields defined in contracts/event.schema.json are used. ``raw`` is left
empty: its internal keys are undocumented, so no keys are invented here. Every
function returns a fresh dict so tests can never share or leak mutations.

Time layout (all the same instant unless noted):
  login / naive / aware  -> 2026-10-18 02:30:00 UTC
  archive                -> 02:41 UTC, upload -> 02:45 UTC, location -> 02:50 UTC
"""
from __future__ import annotations

from typing import Any

CASE_ID = "CASE-TEST-001"
OTHER_CASE_ID = "CASE-TEST-002"
SHA256_A = "a" * 64


def make_event(event_id: str, timestamp: str, **overrides: Any) -> dict[str, Any]:
    """Schema-valid Event with required fields only, plus overrides."""
    event: dict[str, Any] = {
        "event_id": event_id,
        "case_id": CASE_ID,
        "evidence_id": "EVID-001",
        "artifact_ref": "synthetic.csv#row=1",
        "sha256": SHA256_A,
        "timestamp": timestamp,
        "source": "log",
        "action": "synthetic_action",
        "raw": {},
    }
    event.update(overrides)
    return event


def login_event() -> dict[str, Any]:
    return make_event(
        "EV-LOGIN", "2026-10-18T02:30:00Z", source="log", action="login",
        device="DEV-1", actor="user1", ip="203.0.113.10",
    )


def archive_event() -> dict[str, Any]:
    return make_event(
        "EV-ARCHIVE", "2026-10-18T02:41:00Z", source="browser", action="archive_create",
        device="DEV-1", actor="user1", object="bundle.zip",
    )


def upload_event() -> dict[str, Any]:
    return make_event(
        "EV-UPLOAD", "2026-10-18T02:45:00Z", source="pcap", action="file_upload",
        device="DEV-1", actor="user1", object="bundle.zip", ip="198.51.100.7",
    )


def location_event() -> dict[str, Any]:
    return make_event(
        "EV-LOCATION", "2026-10-18T02:50:00Z", source="image", action="location_fix",
        device="DEV-1", location={"lat": 12.9716, "lon": 77.5946},
    )


def minimal_event() -> dict[str, Any]:
    """Required fields only: no device/actor/object/ip/location, and no raw."""
    event = make_event("EV-MINIMAL", "2026-10-18T03:00:00Z")
    del event["raw"]
    return event


def naive_timestamp_event() -> dict[str, Any]:
    """No Z/offset. Role 2 treats this as UTC."""
    return make_event("EV-NAIVE", "2026-10-18T02:30:00")


def aware_timestamp_event() -> dict[str, Any]:
    """+05:30 offset; the same instant as the naive event (02:30 UTC)."""
    return make_event("EV-AWARE", "2026-10-18T08:00:00+05:30")


def all_events() -> list[dict[str, Any]]:
    return [
        login_event(), archive_event(), upload_event(), location_event(),
        minimal_event(), naive_timestamp_event(), aware_timestamp_event(),
    ]
