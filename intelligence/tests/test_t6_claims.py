"""Regression tests for T6 review fixes: OFFHOURS_SESSION timezone and ACTOR_DEVICE_CONSISTENT grading.

Covers:
1. OFFHOURS_SESSION evaluates in configured case timezone (not raw UTC).
2. OFFHOURS_SESSION respects source clock offsets.
3. OFFHOURS_SESSION accounts for source clock uncertainty:
   - status 'all' (fully within window) -> Grade B
   - status 'some' (straddles window boundary) -> Grade C (discounted)
4. ACTOR_DEVICE_CONSISTENT grading:
   - Corroborated across >= 2 independent witness families -> Grade A
   - Only 1 witness family (insufficient corroboration) -> Grade B (never unconditional Grade A)
   - Generic/non-exact identifier -> Grade C
   - Contradiction present -> Grade C
"""
from __future__ import annotations

from datetime import timedelta
from zoneinfo import ZoneInfo

import pytest

from intelligence.claims import (
    generate_actor_device_consistent_claims,
    generate_claims,
    generate_offhours_session_claims,
    generate_same_object_flow_claims,
)
from intelligence.correlate import CandidateRelationship
from intelligence.timeline import SourceClock


def _make_event(
    event_id: str,
    timestamp: str,
    *,
    source: str = "log",
    action: str = "login",
    actor: str = "mira",
    device: str = "laptop-01",
    ip: str = "10.0.0.1",
    obj: str | None = None,
    raw: dict | None = None,
) -> dict:
    return {
        "event_id": event_id,
        "case_id": "CASE-TEST",
        "evidence_id": "EVID-001",
        "artifact_ref": f"{source}.log#1",
        "sha256": "0" * 64,
        "timestamp": timestamp,
        "source": source,
        "action": action,
        "actor": actor,
        "device": device,
        "ip": ip,
        "object": obj,
        "raw": raw or {},
    }


# ---------------------------------------------------------------------------
# T6: OFFHOURS_SESSION Timezone & Uncertainty Tests
# ---------------------------------------------------------------------------

def test_offhours_session_uses_configured_case_timezone():
    """Event at 21:30 UTC is 03:00 IST (Asia/Kolkata).

    Odd-hours window is [00:00, 05:00).
    In UTC, 21:30 is NOT odd hours (hour 21).
    In Asia/Kolkata, 21:30 UTC is 03:00 IST, which IS odd hours (hour 3).
    The claim must record hour 3 and timezone Asia/Kolkata.
    """
    ev = _make_event("EV-1", "2026-10-18T21:30:00Z", action="login", actor="alice")
    tz = ZoneInfo("Asia/Kolkata")

    claims = generate_claims([ev], case_timezone=tz)
    offhours = [c for c in claims if c.type == "OFFHOURS_SESSION"]
    assert len(offhours) == 1
    claim = offhours[0]
    assert claim.params["hour"] == 3
    assert claim.params["timezone"] == "Asia/Kolkata"
    assert claim.grade == "B"
    assert claim.status == "ASSERTED"


def test_offhours_session_not_emitted_when_daytime_in_case_timezone():
    """Event at 02:00 UTC is 07:30 IST (Asia/Kolkata).

    In UTC, 02:00 is odd hours.
    In Asia/Kolkata, 02:00 UTC is 07:30 IST, which is daytime (NOT odd hours).
    When case timezone is Asia/Kolkata, no OFFHOURS_SESSION claim should be emitted.
    """
    ev = _make_event("EV-1", "2026-10-18T02:00:00Z", action="login", actor="alice")
    tz = ZoneInfo("Asia/Kolkata")

    claims = generate_claims([ev], case_timezone=tz)
    offhours = [c for c in claims if c.type == "OFFHOURS_SESSION"]
    assert len(offhours) == 0


def test_offhours_session_accounts_for_source_clock_offset():
    """Clock offset shifts recorded time into odd hours.

    Recorded at 05:10 UTC (daytime, outside [00:00, 05:00)).
    Source clock offset is +20m (source ran 20m ahead of true time).
    True time is 04:50 UTC, which IS odd hours!
    """
    clocks = {
        "log": SourceClock(offset=timedelta(minutes=20), uncertainty=timedelta(0)),
    }
    ev = _make_event("EV-1", "2026-10-18T05:10:00Z", source="log", action="login")

    claims = generate_claims([ev], source_clocks=clocks)
    offhours = [c for c in claims if c.type == "OFFHOURS_SESSION"]
    assert len(offhours) == 1
    assert offhours[0].params["hour"] == 4
    assert offhours[0].grade == "B"


def test_offhours_session_clock_uncertainty_straddling_boundary_gets_grade_c():
    """Event near 05:00 boundary with clock uncertainty straddles window.

    Event at 04:55 UTC with +/- 10m uncertainty.
    Effective interval is [04:45, 05:05].
    Part of the interval is inside [00:00, 05:00) and part is outside.
    T2 status is 'some', so confidence is ambiguous.
    The claim must have boundary_straddle=True and discounted grade 'C'.
    """
    clocks = {
        "log": SourceClock(offset=timedelta(0), uncertainty=timedelta(minutes=10)),
    }
    ev = _make_event("EV-1", "2026-10-18T04:55:00Z", source="log", action="login")

    claims = generate_claims([ev], source_clocks=clocks)
    offhours = [c for c in claims if c.type == "OFFHOURS_SESSION"]
    assert len(offhours) == 1
    claim = offhours[0]
    assert claim.params.get("boundary_straddle") is True
    assert claim.grade == "C"


# ---------------------------------------------------------------------------
# T6: ACTOR_DEVICE_CONSISTENT Grading Tests
# ---------------------------------------------------------------------------

def test_actor_device_consistent_two_independent_families_gets_grade_a():
    """>= 2 independent witness families + exact identifier -> Grade A.

    e1 from family 'log:laptop-1' (source 'log', device 'laptop-1').
    e2 from family 'browser:laptop-1' (source 'browser', device 'laptop-1').
    Two independent witness families corroborate the same actor on device.
    Must receive Grade A and status CORROBORATED.
    """
    e1 = _make_event("EV-1", "2026-10-18T10:00:00Z", source="log", actor="alice", device="laptop-1")
    e2 = _make_event("EV-2", "2026-10-18T10:05:00Z", source="browser", actor="alice", device="laptop-1")
    events_by_id = {e["event_id"]: e for e in [e1, e2]}

    specs = generate_actor_device_consistent_claims([e1, e2], events_by_id)
    assert len(specs) == 1
    claim = specs[0]
    assert claim.status == "CORROBORATED"
    assert claim.grade == "A"
    assert claim.params["supporting_families_count"] == 2
    assert claim.params["actor"] == "alice"
    assert claim.params["device"] == "laptop-1"


def test_actor_device_consistent_single_witness_family_gets_grade_b():
    """1 witness family (insufficient independent corroboration) -> Grade B (NOT Grade A).

    Two events from the SAME source ('log') and SAME device ('laptop-1').
    They belong to only 1 witness family ('log:laptop-1').
    Without independent cross-family corroboration, the claim must NOT receive Grade A.
    It receives Grade B with status ASSERTED.
    """
    e1 = _make_event("EV-1", "2026-10-18T10:00:00Z", source="log", actor="alice", device="laptop-1")
    e2 = _make_event("EV-2", "2026-10-18T10:05:00Z", source="log", actor="alice", device="laptop-1")
    events_by_id = {e["event_id"]: e for e in [e1, e2]}

    specs = generate_actor_device_consistent_claims([e1, e2], events_by_id)
    assert len(specs) == 1
    claim = specs[0]
    assert claim.status == "ASSERTED"
    assert claim.grade == "B"
    assert claim.grade != "A"
    assert claim.params["supporting_families_count"] == 1


def test_actor_device_consistent_generic_identifier_gets_grade_c():
    """Generic/unknown actor or device does not qualify for Grade A or B -> Grade C.

    e1 and e2 have actor='unknown' across two independent families.
    Even though multi-family, generic identifier lacks exactness -> Grade C.
    """
    e1 = _make_event("EV-1", "2026-10-18T10:00:00Z", source="log", actor="unknown", device="laptop-1")
    e2 = _make_event("EV-2", "2026-10-18T10:05:00Z", source="browser", actor="unknown", device="laptop-1")
    events_by_id = {e["event_id"]: e for e in [e1, e2]}

    specs = generate_actor_device_consistent_claims([e1, e2], events_by_id)
    assert len(specs) == 1
    claim = specs[0]
    assert claim.grade == "C"

# SAME_OBJECT_FLOW regression tests

def _candidate_relationship(candidate_type: str, canonical_entities: dict) -> CandidateRelationship:
    return CandidateRelationship(
        candidate_id="CAND-TEST", source_event_id="EV-1", target_event_id="EV-2",
        candidate_type=candidate_type, matched_signals=[], canonical_entities=canonical_entities,
        temporal_delta=120.0, sequence_compatibility="COMPATIBLE",
        contradiction_signals=[], score=1.0, promotion_decision=True, reason_codes=[],
    )


def test_same_object_flow_rejects_event_correlation_without_exact_object():
    e1 = _make_event("EV-1", "2026-10-18T10:00:00Z", action="login", obj="/home/alice")
    e2 = _make_event("EV-2", "2026-10-18T10:02:00Z", action="archive_create", obj="incident.zip")
    link = _candidate_relationship("EVENT_CORRELATION", {"shared_object": None, "shared_content_hash": None})
    assert generate_same_object_flow_claims([link], {e["event_id"]: e for e in (e1, e2)}) == []


def test_same_object_flow_rejects_missing_or_placeholder_shared_identifier():
    e1 = _make_event("EV-1", "2026-10-18T10:00:00Z", obj="incident.zip")
    e2 = _make_event("EV-2", "2026-10-18T10:02:00Z", obj="incident.zip")
    for identifier in (None, "", "unknown", "none", "null", "n/a"):
        link = _candidate_relationship("SAME_OBJECT_FLOW", {"shared_object": identifier, "shared_content_hash": None})
        assert generate_same_object_flow_claims([link], {e["event_id"]: e for e in (e1, e2)}) == []


@pytest.mark.parametrize("identifier", ["abcd1234", "8000000000000000"])
def test_same_object_flow_rejects_short_hex_and_perceptual_shared_objects(identifier: str):
    e1 = _make_event("EV-1", "2026-10-18T10:00:00Z", obj=identifier)
    e2 = _make_event("EV-2", "2026-10-18T10:02:00Z", obj=identifier)
    link = _candidate_relationship(
        "SAME_OBJECT_FLOW",
        {"shared_object": identifier, "shared_content_hash": None},
    )

    assert generate_same_object_flow_claims([link], {e["event_id"]: e for e in (e1, e2)}) == []


@pytest.mark.parametrize("identifier", ["abcd1234", "8000000000000000"])
def test_normal_correlation_rejects_short_hex_and_perceptual_object_identifiers(identifier: str):
    events = [
        _make_event("EV-1", "2026-10-18T10:00:00Z", action="archive_create", obj=identifier),
        _make_event("EV-2", "2026-10-18T10:02:00Z", action="file_upload", obj=identifier),
    ]

    claims = [claim for claim in generate_claims(events) if claim.type == "SAME_OBJECT_FLOW"]

    assert claims == []


def test_same_object_flow_preserves_exact_shared_object_claim():
    e1 = _make_event("EV-1", "2026-10-18T10:00:00Z", action="archive_create", obj="incident.zip")
    e2 = _make_event("EV-2", "2026-10-18T10:03:00Z", action="file_upload", obj="incident.zip")
    link = _candidate_relationship("SAME_OBJECT_FLOW", {"shared_object": "incident.zip", "shared_content_hash": None})
    claims = generate_same_object_flow_claims([link], {e["event_id"]: e for e in (e1, e2)})
    assert len(claims) == 1
    assert claims[0].params["object"] == "incident.zip"


def test_same_object_flow_uses_valid_hash_when_short_object_identifier_is_invalid():
    e1 = _make_event("EV-1", "2026-10-18T10:00:00Z", obj="incident.zip")
    e2 = _make_event("EV-2", "2026-10-18T10:02:00Z", obj="incident.zip")
    digest = "c" * 64
    link = _candidate_relationship(
        "SAME_OBJECT_FLOW",
        {"shared_object": "abcd1234", "shared_content_hash": digest},
    )

    claims = generate_same_object_flow_claims(
        [link], {e["event_id"]: e for e in (e1, e2)}
    )

    assert len(claims) == 1
    assert claims[0].params["object"] == digest


def test_same_object_flow_uses_sha256_through_normal_correlation_path():
    digest = "d" * 64
    events = [
        _make_event(
            "EV-1", "2026-10-18T10:00:00Z", source="log",
            action="archive_create", raw={"content_hash": digest},
        ),
        _make_event(
            "EV-2", "2026-10-18T10:02:00Z", source="browser",
            action="file_upload", raw={"sha256": digest},
        ),
    ]

    claims = [claim for claim in generate_claims(events) if claim.type == "SAME_OBJECT_FLOW"]

    assert len(claims) == 1
    assert claims[0].params["object"] == digest
