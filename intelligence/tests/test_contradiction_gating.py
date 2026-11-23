"""Regression tests for PR #18 review: contradiction claims must be evidence-gated.

Covers ``generate_attribution_conflict_claims`` and
``generate_cross_source_temporal_conflict_claims`` in ``intelligence/claims.py``.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from intelligence.claims import (
    generate_attribution_conflict_claims,
    generate_claims,
    generate_cross_source_temporal_conflict_claims,
)
from intelligence.timeline import SourceClock

HASH_A = "a" * 64
HASH_B = "b" * 64
NO_CLOCKS: dict[str, SourceClock] = {}


def _ev(
    event_id: str,
    action: str,
    timestamp: str | None,
    *,
    source: str = "log",
    actor: Any = "mira.chen",
    device: Any = "field-laptop-07",
    obj: str = "CASE-001.tar.gz",
    raw: dict[str, Any] | None = None,
    family: str | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "event_id": event_id,
        "source": source,
        "action": action,
        "actor": actor,
        "device": device,
        "object": obj,
        "ip": "198.51.100.42",
        "raw": dict(raw or {}),
    }
    if timestamp is not None:
        event["timestamp"] = timestamp
    if family:
        event["family"] = family
    return event


def _attr(events: list[dict[str, Any]]):
    return generate_attribution_conflict_claims(events, {e["event_id"]: e for e in events})


def _temporal(events: list[dict[str, Any]], clocks: dict[str, SourceClock] | None = None):
    return generate_cross_source_temporal_conflict_claims(
        events, {e["event_id"]: e for e in events}, source_clocks=NO_CLOCKS if clocks is None else clocks
    )


# =============================================================================
# 1. Temporal contradiction gating
# =============================================================================

class TestTemporalContradiction:
    def test_same_filename_normal_upload_refresh_sequence_no_claim(self):
        events = [
            _ev("U1", "upload", "2026-10-17T17:47:00Z", source="browser",
                obj="https://external-storage.example/CASE-001.tar.gz"),
            _ev("R1", "session_refresh", "2026-10-17T17:48:00Z"),
        ]
        assert _temporal(events) == []

    def test_upload_refresh_never_claimed_even_out_of_order(self):
        # No documented invariant relates session_refresh to uploads.
        events = [
            _ev("U1", "upload", "2026-10-17T17:47:00Z", source="browser",
                obj="https://external-storage.example/CASE-001.tar.gz", raw={"content_hash": HASH_A}),
            _ev("R1", "session_refresh", "2026-10-17T10:00:00Z", raw={"content_hash": HASH_A}),
        ]
        assert _temporal(events) == []

    def test_same_filename_unrelated_actors_or_sessions_no_claim(self):
        events = [
            _ev("C1", "archive_create", "2026-10-17T18:00:00Z", actor="alice",
                raw={"session_id": "S-1"}),
            _ev("U1", "upload", "2026-10-17T17:00:00Z", source="browser", actor="bob",
                obj="https://x.example/CASE-001.tar.gz", raw={"session_id": "S-2"}),
        ]
        assert _temporal(events) == []

    def test_different_timestamps_alone_no_claim(self):
        # Upload long before a same-named archive creation, but no content identity.
        events = [
            _ev("C1", "archive_create", "2026-10-17T18:00:00Z"),
            _ev("U1", "upload", "2026-10-17T09:00:00Z", source="browser",
                obj="https://x.example/CASE-001.tar.gz"),
        ]
        assert _temporal(events) == []

    def test_missing_timestamp_no_claim(self):
        events = [
            _ev("C1", "archive_create", None, raw={"content_hash": HASH_A}),
            _ev("U1", "upload", "2026-10-17T09:00:00Z", source="browser",
                obj="https://x.example/CASE-001.tar.gz", raw={"content_hash": HASH_A}),
        ]
        assert _temporal(events) == []
        events[0]["timestamp"] = ""
        assert _temporal(events) == []
        events[0]["timestamp"] = "not-a-time"
        assert _temporal(events) == []

    def test_timezone_aware_and_naive_consistent(self):
        # 23:00+05:30 == 17:30Z.  Naive values are UTC (common.parse_timestamp policy).
        same_instant = [
            _ev("C1", "archive_create", "2026-10-17T23:00:00+05:30", raw={"content_hash": HASH_A}),
            _ev("U1", "upload", "2026-10-17T17:30:00", source="browser",
                obj="https://x.example/f.tar.gz", raw={"content_hash": HASH_A}),
        ]
        assert _temporal(same_instant) == []

        # Naive 17:29 UTC is definitely before 17:30Z.
        before = [
            _ev("C1", "archive_create", "2026-10-17T23:00:00+05:30", raw={"content_hash": HASH_A}),
            _ev("U1", "upload", "2026-10-17T17:29:00", source="browser",
                obj="https://x.example/f.tar.gz", raw={"content_hash": HASH_A}),
        ]
        claims = _temporal(before)
        assert len(claims) == 1
        assert claims[0].params["min_violation_seconds"] == 60.0

        # Raw string ordering would be misleading: "17:31" (naive UTC) < "23:00+05:30" as
        # text, but it is AFTER creation in true time -> no claim.
        after = [
            _ev("C1", "archive_create", "2026-10-17T23:00:00+05:30", raw={"content_hash": HASH_A}),
            _ev("U1", "upload", "2026-10-17T17:31:00", source="browser",
                obj="https://x.example/f.tar.gz", raw={"content_hash": HASH_A}),
        ]
        assert _temporal(after) == []

    def test_genuine_violation_strongly_matched_produces_claim(self):
        events = [
            _ev("C1", "archive_create", "2026-10-17T18:00:00Z", raw={"content_hash": HASH_A},
                family="system_log"),
            _ev("U1", "upload", "2026-10-17T17:00:00Z", source="browser",
                obj="https://x.example/renamed.bin", raw={"content_hash": HASH_A},
                family="browser_history"),
        ]
        claims = _temporal(events)
        assert len(claims) == 1
        claim = claims[0]
        assert claim.type == "LOCATION_CONFLICT"
        assert claim.params["invariant"] == "TC-1_creation_precedes_transfer"
        assert claim.params["object"] == HASH_A
        assert claim.params["min_violation_seconds"] == 3600.0
        roles = {(e.ref_id, e.role) for e in claim.edges}
        assert roles == {("C1", "SUPPORTS"), ("U1", "CONTRADICTS")}

    def test_different_content_hash_no_claim(self):
        events = [
            _ev("C1", "archive_create", "2026-10-17T18:00:00Z", raw={"content_hash": HASH_A}),
            _ev("U1", "upload", "2026-10-17T17:00:00Z", source="browser",
                obj="https://x.example/CASE-001.tar.gz", raw={"content_hash": HASH_B}),
        ]
        assert _temporal(events) == []

    def test_normal_creation_then_upload_no_claim(self):
        events = [
            _ev("C1", "archive_create", "2026-10-17T17:00:00Z", raw={"content_hash": HASH_A}),
            _ev("U1", "upload", "2026-10-17T17:05:00Z", source="browser",
                obj="https://x.example/f", raw={"content_hash": HASH_A}),
        ]
        assert _temporal(events) == []

    def test_clock_uncertainty_prevents_unsupported_certainty(self):
        events = [
            _ev("C1", "archive_create", "2026-10-17T17:02:00Z", raw={"content_hash": HASH_A}),
            _ev("U1", "upload", "2026-10-17T17:00:00Z", source="browser",
                obj="https://x.example/f", raw={"content_hash": HASH_A}),
        ]
        assert len(_temporal(events)) == 1  # exact clocks: 2 min violation
        clocks = {"browser": SourceClock(uncertainty=timedelta(minutes=3))}
        assert _temporal(events, clocks) == []  # intervals overlap -> not definite

    def test_clock_offset_correction_applied(self):
        # Browser clock runs 5 min ahead: recorded 17:03 really happened 16:58... and
        # a recorded 17:03 with -5 min offset (behind) really happened 17:08.
        events = [
            _ev("C1", "archive_create", "2026-10-17T17:05:00Z", raw={"content_hash": HASH_A}),
            _ev("U1", "upload", "2026-10-17T17:03:00Z", source="browser",
                obj="https://x.example/f", raw={"content_hash": HASH_A}),
        ]
        behind = {"browser": SourceClock(offset=timedelta(minutes=-5))}
        assert _temporal(events, behind) == []

    def test_duplicate_records_yield_single_claim(self):
        create = _ev("C1", "archive_create", "2026-10-17T18:00:00Z", raw={"content_hash": HASH_A})
        upload = _ev("U1", "upload", "2026-10-17T17:00:00Z", source="browser",
                     obj="https://x.example/f", raw={"content_hash": HASH_A})
        dup = dict(upload, event_id="U1-dup")
        assert len(_temporal([create, upload, dup])) == 1


# =============================================================================
# 2. Attribution contradiction gating
# =============================================================================

class TestAttributionContradiction:
    def test_independent_same_filename_archives_no_claim(self):
        events = [
            _ev("A1", "archive_create", "2026-10-17T17:00:00Z", actor="mira.chen", device="laptop-1"),
            _ev("A2", "archive_create", "2026-10-17T17:02:00Z", actor="unknown.65",
                device="unrecognized-5"),
        ]
        assert _attr(events) == []

    @pytest.mark.parametrize("missing", [None, "", "   "])
    def test_one_missing_actor_no_claim(self, missing):
        events = [
            _ev("A1", "archive_create", "2026-10-17T17:00:00Z", raw={"content_hash": HASH_A}),
            _ev("A2", "archive_create", "2026-10-17T17:02:00Z", actor=missing,
                raw={"content_hash": HASH_A}),
        ]
        assert _attr(events) == []

    def test_one_missing_device_no_claim(self):
        events = [
            _ev("A1", "archive_create", "2026-10-17T17:00:00Z", raw={"content_hash": HASH_A}),
            _ev("A2", "archive_create", "2026-10-17T17:02:00Z", device=None,
                raw={"content_hash": HASH_A}),
        ]
        assert _attr(events) == []

    def test_both_actor_and_device_missing_no_claim(self):
        events = [
            _ev("A1", "archive_create", "2026-10-17T17:00:00Z", raw={"content_hash": HASH_A}),
            _ev("A2", "archive_create", "2026-10-17T17:02:00Z", actor=None, device=None,
                raw={"content_hash": HASH_A}),
        ]
        assert _attr(events) == []

    @pytest.mark.parametrize("placeholder", ["unknown", "UNKNOWN", "null", "None", "n/a", "-", "undefined"])
    def test_placeholders_are_not_identities(self, placeholder):
        events = [
            _ev("A1", "archive_create", "2026-10-17T17:00:00Z", raw={"content_hash": HASH_A}),
            _ev("A2", "archive_create", "2026-10-17T17:02:00Z", actor=placeholder,
                device=placeholder, raw={"content_hash": HASH_A}),
        ]
        assert _attr(events) == []

    def test_different_sessions_same_filename_no_claim(self):
        events = [
            _ev("A1", "archive_create", "2026-10-17T17:00:00Z", actor="alice",
                raw={"session_id": "S-1"}),
            _ev("A2", "archive_create", "2026-10-17T17:02:00Z", actor="bob",
                raw={"session_id": "S-2"}),
        ]
        assert _attr(events) == []

    def test_strongly_matched_incompatible_attribution_claim(self):
        events = [
            _ev("A1", "archive_create", "2026-10-17T17:00:00Z", actor="mira.chen",
                device="laptop-1", raw={"content_hash": HASH_A}),
            _ev("A2", "archive_create", "2026-10-17T17:02:00Z", actor="raj.k",
                device="desktop-9", raw={"content_hash": HASH_A}),
        ]
        claims = _attr(events)
        assert len(claims) == 1
        claim = claims[0]
        assert claim.params["conflicting_fields"] == ["actor", "device"]
        assert claim.params["instance_match"] == {"content_hash": HASH_A}
        assert {(e.ref_id, e.role) for e in claim.edges} == {("A1", "SUPPORTS"), ("A2", "CONTRADICTS")}

    def test_session_match_with_only_actor_conflict_reports_actor_only(self):
        events = [
            _ev("A1", "archive_create", "2026-10-17T17:00:00Z", actor="alice",
                raw={"session_id": "S-1"}),
            _ev("A2", "archive_create", "2026-10-17T17:02:00Z", actor="bob",
                raw={"session_id": "S-1"}),
        ]
        claims = _attr(events)
        assert len(claims) == 1
        assert claims[0].params["conflicting_fields"] == ["actor"]

    def test_identical_attribution_no_claim(self):
        events = [
            _ev("A1", "archive_create", "2026-10-17T17:00:00Z", actor="Mira.Chen ",
                raw={"content_hash": HASH_A}),
            _ev("A2", "archive_create", "2026-10-17T17:02:00Z", actor="mira.chen",
                raw={"content_hash": HASH_A}),
        ]
        assert _attr(events) == []

    def test_duplicate_events_single_claim(self):
        a1 = _ev("A1", "archive_create", "2026-10-17T17:00:00Z", actor="alice",
                 raw={"content_hash": HASH_A, "session_id": "S-1"})
        a2 = _ev("A2", "archive_create", "2026-10-17T17:02:00Z", actor="bob",
                 raw={"content_hash": HASH_A, "session_id": "S-1"})
        a2_dup = dict(a2, event_id="A2-dup")
        claims = _attr([a1, a2, a2_dup])
        assert len(claims) == 1
        assert claims[0].params["instance_match"] == {"content_hash": HASH_A, "session_id": "S-1"}

    def test_duplicate_records_of_one_observation_not_self_conflicting(self):
        a1 = _ev("A1", "archive_create", "2026-10-17T17:00:00Z", raw={"content_hash": HASH_A})
        assert _attr([a1, dict(a1, event_id="A1-dup")]) == []


def test_generate_claims_end_to_end_ignores_unsupported_contradictions():
    """Simulator-shaped incident: no LOCATION_CONFLICT from filename-only matches."""
    events = [
        _ev("A1", "archive_create", "2026-10-17T17:00:00Z", family="system_log"),
        _ev("A2", "archive_create", "2026-10-17T17:02:00Z", actor="unknown.65",
            device="unrecognized-5", family="system_log"),
        _ev("U1", "upload", "2026-10-17T17:15:00Z", source="browser",
            obj="https://external-storage.example/CASE-001.tar.gz", family="browser_history"),
        _ev("R1", "session_refresh", "2026-10-17T17:13:00Z", family="authentication"),
    ]
    claims = generate_claims(events, source_clocks=NO_CLOCKS)
    rule_ids = {c.rule_id for c in claims if c.type == "LOCATION_CONFLICT"}
    assert "rule_attribution_conflict" not in rule_ids
    assert "rule_cross_source_temporal_conflict" not in rule_ids
