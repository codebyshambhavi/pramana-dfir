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
        "action": "login",  # the odd-hour rule only considers login/session actions
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
    assert "odd hours" in f["claim"].lower()
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
    e1 = make_event("EV-ODD", "2026-10-18T01:00:00Z")
    e2 = make_event("EV-NORMAL", "2026-10-18T12:00:00Z")
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

# ---------------------------------------------------------------------------
# Stage 0 / T2: eligibility, case timezone, source clocks
# ---------------------------------------------------------------------------
from datetime import timedelta, timezone  # noqa: E402
from zoneinfo import ZoneInfo  # noqa: E402

from intelligence import config  # noqa: E402
from intelligence.timeline import SourceClock  # noqa: E402

IST = ZoneInfo("Asia/Kolkata")
MIN = timedelta(minutes=1)


@pytest.mark.parametrize("action", ["login", "auth", "authenticate", "session_start", "LOGIN", " Login "])
def test_session_type_actions_are_eligible(action) -> None:
    e = make_event("EV-1", "2026-10-18T02:17:00Z", action=action)
    assert len(find_anomalies([e], case_timezone=timezone.utc)) == 1


@pytest.mark.parametrize(
    "source, action",
    [
        ("chat", "location_sync"),
        ("chat", "message_sent"),
        ("image", "image_captured"),
        ("pcap", "DNS query vault.example.test"),
        ("pcap", "DNS response vault.example.test"),
        ("log", "archive_create"),
        ("browser", "file_upload"),
        ("log", "synthetic_action"),
    ],
)
def test_non_session_events_never_trigger_odd_hour_rule(source, action) -> None:
    e = make_event("EV-1", "2026-10-18T02:17:00Z", source=source, action=action)
    assert find_anomalies([e], case_timezone=timezone.utc) == []


def test_odd_hour_is_evaluated_in_the_case_timezone_not_utc() -> None:
    # 02:17Z is odd in UTC but 07:47 in IST -> not odd there.
    early_utc = make_event("EV-A", "2026-10-18T02:17:00Z")
    assert len(find_anomalies([early_utc], case_timezone=timezone.utc)) == 1
    assert find_anomalies([early_utc], case_timezone=IST) == []
    # 21:30Z is 03:00 IST (odd) but 21:30 UTC (not odd).
    late_utc = make_event("EV-B", "2026-10-18T21:30:00Z")
    assert find_anomalies([late_utc], case_timezone=timezone.utc) == []
    f = find_anomalies([late_utc], case_timezone=IST)
    assert len(f) == 1 and "03:00" in f[0]["claim"] and "Asia/Kolkata" in f[0]["claim"]


def test_ist_boundaries_use_half_hour_offset_correctly() -> None:
    # 23:29:59Z = 04:59:59 IST (odd); 23:30:00Z = 05:00:00 IST (end of window, not odd)
    assert len(find_anomalies([make_event("EV-1", "2026-10-18T23:29:59Z")], case_timezone=IST)) == 1
    assert find_anomalies([make_event("EV-2", "2026-10-18T23:30:00Z")], case_timezone=IST) == []
    # 18:30:00Z = 00:00:00 IST next day (start of window, odd)
    assert len(find_anomalies([make_event("EV-3", "2026-10-18T18:30:00Z")], case_timezone=IST)) == 1


def test_case_timezone_comes_from_configuration_by_default(monkeypatch) -> None:
    e = make_event("EV-1", "2026-10-18T21:30:00Z")
    monkeypatch.delenv(config.TIMEZONE_ENV_VAR, raising=False)
    assert find_anomalies([e]) == []                          # default UTC: 21:30 not odd
    monkeypatch.setenv(config.TIMEZONE_ENV_VAR, "Asia/Kolkata")
    assert len(find_anomalies([e])) == 1                      # IST: 03:00 odd


def test_raw_timestamp_is_not_modified() -> None:
    e = make_event("EV-1", "2026-10-18T21:30:00Z")
    before = dict(e)
    find_anomalies([e], case_timezone=IST, source_clocks={"log": SourceClock(offset=4 * MIN)})
    assert e == before


def test_source_clock_offset_changes_the_local_time_used() -> None:
    # Recorded 05:05Z by a log clock running 10 min ahead => true 04:55Z => odd (UTC case).
    e = make_event("EV-1", "2026-10-18T05:05:00Z", source="log")
    assert find_anomalies([e], case_timezone=timezone.utc, source_clocks={}) == []
    f = find_anomalies([e], case_timezone=timezone.utc, source_clocks={"log": SourceClock(offset=10 * MIN)})
    assert len(f) == 1 and f[0]["confidence"] == 0.7
    assert "offset +600s" in f[0]["reasoning"]


def test_clock_uncertainty_straddling_the_boundary_is_reported_as_ambiguous() -> None:
    # Raw 05:02Z, +-10 min => true time in [04:52, 05:12]: part inside, part outside the window.
    e = make_event("EV-1", "2026-10-18T05:02:00Z", source="log")
    f = find_anomalies([e], case_timezone=timezone.utc, source_clocks={"log": SourceClock(uncertainty=10 * MIN)})
    assert len(f) == 1
    assert f[0]["confidence"] == 0.4 < 0.7
    assert "may fall" in f[0]["claim"] and "uncertainty" in f[0]["claim"]


def test_clock_uncertainty_fully_outside_or_inside_window() -> None:
    clocks = {"log": SourceClock(uncertainty=2 * MIN)}
    outside = make_event("EV-1", "2026-10-18T05:30:00Z", source="log")
    inside = make_event("EV-2", "2026-10-18T02:00:00Z", source="log")
    assert find_anomalies([outside], case_timezone=timezone.utc, source_clocks=clocks) == []
    f = find_anomalies([inside], case_timezone=timezone.utc, source_clocks=clocks)
    assert len(f) == 1 and f[0]["confidence"] == 0.7


def test_clock_for_a_different_source_does_not_apply() -> None:
    e = make_event("EV-1", "2026-10-18T05:05:00Z", source="log")
    assert find_anomalies([e], case_timezone=timezone.utc, source_clocks={"chat": SourceClock(offset=10 * MIN)}) == []
