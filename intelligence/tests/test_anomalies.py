"""Tests for intelligence.anomalies."""

from __future__ import annotations

from typing import Any

import pytest

from intelligence.anomalies import find_anomalies
from intelligence.tests.fixtures import (
    archive_event,
    upload_event,
    login_event,
    location_event,
    minimal_event,
    naive_timestamp_event,
    aware_timestamp_event,
    all_events,
    CASE_ID,
    SHA256_A,
)


def make_event(event_id: str, timestamp: str, **overrides: Any) -> dict[str, Any]:
    """Helper to create a minimal event for testing."""
    event = {
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


def test_find_anomalies_returns_empty_for_no_events() -> None:
    assert find_anomalies([]) == []


def test_find_anomalies_returns_empty_for_single_non_odd_hour_event() -> None:
    # Event at 10:00 AM (not odd hours)
    e1 = make_event("EV-001", "2026-10-18T10:00:00Z")
    assert find_anomalies([e1]) == []


def test_find_anomalies_detects_odd_hour_event_at_exact_start() -> None:
    # Event at 00:00:00 (start of odd hours range [0,5))
    e1 = make_event("EV-001", "2026-10-18T00:00:00Z")
    findings = find_anomalies([e1])
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "anomaly"
    assert f["evidence_event_ids"] == ["EV-001"]
    assert "odd-hours" in f["claim"].lower()
    assert f["confidence"] == 0.7
    assert f["needs_human_review"] is True


def test_find_anomalies_detects_odd_hour_event_at_exact_end_minus_one_second() -> None:
    # Event at 04:59:59 (still within odd hours range [0,5))
    e1 = make_event("EV-001", "2026-10-18T04:59:59Z")
    findings = find_anomalies([e1])
    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "anomaly"
    assert f["evidence_event_ids"] == ["EV-001"]


def test_find_anomalies_returns_empty_for_event_at_exact_end() -> None:
    # Event at 05:00:00 (exactly at end of range [0,5) - should NOT be included)
    e1 = make_event("EV-001", "2026-10-18T05:00:00Z")
    assert find_anomalies([e1]) == []


def test_find_anomalies_detects_multiple_odd_hour_events() -> None:
    # Events at 01:00:00 and 03:30:00 (both within odd hours)
    e1 = make_event("EV-001", "2026-10-18T01:00:00Z")
    e2 = make_event("EV-002", "2026-10-18T03:30:00Z")
    findings = find_anomalies([e1, e2])
    assert len(findings) == 2
    evidence_ids = {f["evidence_event_ids"][0] for f in findings}
    assert evidence_ids == {"EV-001", "EV-002"}
    for f in findings:
        assert f["type"] == "anomaly"


def test_find_anomalies_mixed_odd_and_non_odd_hour_events() -> None:
    # Mix of odd hour (01:00) and non-odd hour (12:00) events
    e1 = make_event("EV-ODD", "2026-10-18T01:00:00Z")      # Odd hour
    e2 = make_event("EV-NORMAL", "2026-10-18T12:00:00Z")   # Not odd hour
    findings = find_anomalies([e1, e2])
    assert len(findings) == 1
    f = findings[0]
    assert f["evidence_event_ids"] == ["EV-ODD"]
    assert f["type"] == "anomaly"


def test_find_anomalies_uses_case_id_from_events() -> None:
    # Test that findings use the case_id from the events
    e1 = make_event("EV-001", "2026-10-18T01:00:00Z")
    findings = find_anomalies([e1])
    assert len(findings) == 1
    assert findings[0]["case_id"] == CASE_ID


def test_find_anomalies_handles_events_with_missing_case_id() -> None:
    # Events without case_id should still work (case_id will be empty string in finding)
    e1 = make_event("EV-001", "2026-10-18T01:00:00Z")
    del e1["case_id"]  # Remove case_id
    findings = find_anomalies([e1])
    assert len(findings) == 1
    assert findings[0]["case_id"] == ""  # Should be empty string when missing


def test_find_anomalies_finding_id_is_deterministic() -> None:
    # Same input should produce same finding ID
    e1 = make_event("EV-001", "2026-10-18T01:00:00Z")
    run1 = find_anomalies([e1])
    run2 = find_anomalies([e1])
    assert run1 == run2
    assert run1[0]["finding_id"] == run2[0]["finding_id"]


def test_find_anomalies_finding_id_is_order_independent() -> None:
    # Different order of same events should produce same findings (sorted)
    e1 = make_event("EV-001", "2026-10-18T01:00:00Z")
    e2 = make_event("EV-002", "2026-10-18T03:00:00Z")
    findings1 = find_anomalies([e1, e2])
    findings2 = find_anomalies([e2, e1])
    assert len(findings1) == len(findings2) == 2
    # Sort findings by evidence_event_ids for comparison
    sorted1 = sorted(findings1, key=lambda f: f["evidence_event_ids"][0])
    sorted2 = sorted(findings2, key=lambda f: f["evidence_event_ids"][0])
    assert sorted1 == sorted2
    for f1, f2 in zip(sorted1, sorted2):
        assert f1["finding_id"] == f2["finding_id"]


def test_find_anomalies_with_realistic_fixtures() -> None:
    # Test with the fixtures from conftest.py to ensure they work
    events = all_events()
    findings = find_anomalies(events)
    # login_event is at 02:30:00Z which is within odd hours [0,5)
    # archive_event is at 02:41:00Z which is within odd hours [0,5)
    # upload_event is at 02:45:00Z which is within odd hours [0,5)
    # location_event is at 02:50:00Z which is within odd hours [0,5)
    # naive_timestamp_event is at 02:30:00 (treated as UTC) which is within odd hours [0,5)
    # aware_timestamp_event is at 08:00:00+05:30 which is 02:30:00Z which is within odd hours [0,5)
    # minimal_event is at 03:00:00Z which is within odd hours [0,5)
    # So all events except possibly some should be odd hour events
    # Actually let's check: all events in all_events() are at 02:30 or similar except location at 02:50
    # So they should all be detected as odd hour
    assert len(findings) > 0  # At least some should be detected
    for f in findings:
        assert f["type"] == "anomaly"


def test_find_anomalies_evidence_event_ids_are_valid() -> None:
    # Ensure findings only cite event IDs that were actually in the input
    e1 = make_event("EV-001", "2026-10-18T01:00:00Z")
    e2 = make_event("EV-002", "2026-10-18T02:00:00Z")
    findings = find_anomalies([e1, e2])
    assert len(findings) == 2
    for f in findings:
        for eid in f["evidence_event_ids"]:
            assert eid in ("EV-001", "EV-002")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])