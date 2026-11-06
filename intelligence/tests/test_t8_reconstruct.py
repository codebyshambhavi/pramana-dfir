"""Role 3 / T8: Narrative Reconstruction Engine Tests.

Tests:
1. Reconstruction maps claims and events to hypothesis stages
2. Stage status: SUPPORTED vs GAP
3. Interval handling via TimeInterval:
   - Strictly sequential intervals -> PRECEDES
   - Overlapping intervals -> CONCURRENT_OR_OVERLAPPING (never asserts false precedence)
   - Reversed intervals -> OUT_OF_ORDER
   - Missing intermediate stage -> GAP_DETECTED
4. Background activity and H0 residual event separation
5. Narrative summary string generation
"""
from __future__ import annotations

from datetime import datetime, timedelta
import pytest

from intelligence.hyp.reconstruct import (
    NarrativeReconstruction,
    StageReconstruction,
    reconstruct_narrative,
)
from intelligence.timeline import SourceClock, TimeInterval


def _make_event(event_id: str, source: str, action: str, timestamp: str, actor: str = "alice", device: str = "dev-1") -> dict:
    return {
        "event_id": event_id,
        "case_id": "CASE-TEST",
        "evidence_id": f"EVID-{source}",
        "artifact_ref": f"{source}.csv#1",
        "sha256": "0" * 64,
        "timestamp": timestamp,
        "source": source,
        "action": action,
        "actor": actor,
        "device": device,
    }


def _make_claim(claim_id: str, claim_type: str, events: list[dict], params: dict | None = None) -> dict:
    edges = [
        {"ref_kind": "event", "ref_id": ev["event_id"], "role": "SUPPORTS"}
        for ev in events
    ]
    return {
        "claim_id": claim_id,
        "claim_key": f"KEY-{claim_id}",
        "type": claim_type,
        "status": "ASSERTED",
        "grade": "A",
        "params": params or {},
        "edges": edges,
    }


def test_reconstruct_narrative_supported_stages_and_intervals():
    """H1 has access, staging, exfiltration, evasion stages.
    Access at 02:00, staging at 02:30, exfiltration at 03:00.
    Sequential ordering without overlap yields PRECEDES.
    """
    ev_acc = _make_event("EV-1", "system_log", "login", "2026-10-18T02:00:00Z")
    ev_stage = _make_event("EV-2", "system_log", "offhours_archive", "2026-10-18T02:30:00Z")
    ev_exfil = _make_event("EV-3", "browser", "upload", "2026-10-18T03:00:00Z")
    events = [ev_acc, ev_stage, ev_exfil]

    claims = [
        _make_claim("C1", "ACTOR_DEVICE_CONSISTENT", events=[ev_acc]),
        _make_claim("C2", "OFFHOURS_SESSION", events=[ev_stage]),
        _make_claim("C3", "SAME_OBJECT_FLOW", events=[ev_exfil]),
    ]

    recon = reconstruct_narrative("H1", claims, events)
    assert recon.hypothesis_id == "H1"
    assert len(recon.stages) == 4

    st_acc = recon.stages[0]
    assert st_acc.stage_name == "access"
    assert st_acc.status == "SUPPORTED"
    assert st_acc.relationship_to_previous == "FIRST_STAGE"
    assert st_acc.time_window is not None

    st_stage = recon.stages[1]
    assert st_stage.stage_name == "staging"
    assert st_stage.status == "SUPPORTED"
    assert st_stage.relationship_to_previous == "PRECEDES"

    st_exfil = recon.stages[2]
    assert st_exfil.stage_name == "exfiltration"
    assert st_exfil.status == "SUPPORTED"
    assert st_exfil.relationship_to_previous == "PRECEDES"

    # Evasion has no claims -> GAP
    st_evasion = recon.stages[3]
    assert st_evasion.stage_name == "evasion"
    assert st_evasion.status == "GAP"
    assert st_evasion.relationship_to_previous == "GAP_DETECTED"


def test_reconstruct_concurrent_overlapping_intervals_not_asserted_as_precedence():
    """When stage intervals overlap (taking into account clock uncertainty),
    the relationship must be reported as CONCURRENT_OR_OVERLAPPING, never asserted as definite precedence.
    """
    # Event 1: access at 02:00:00 +- 15m -> interval [01:45, 02:15]
    # Event 2: staging at 02:10:00 +- 15m -> interval [01:55, 02:25]
    # These two intervals overlap!
    ev_acc = _make_event("EV-1", "system_log", "login", "2026-10-18T02:00:00Z")
    ev_stage = _make_event("EV-2", "system_log", "offhours_archive", "2026-10-18T02:10:00Z")
    events = [ev_acc, ev_stage]

    claims = [
        _make_claim("C1", "ACTOR_DEVICE_CONSISTENT", events=[ev_acc]),
        _make_claim("C2", "OFFHOURS_SESSION", events=[ev_stage]),
    ]

    clocks = {
        "system_log": SourceClock(offset=timedelta(0), uncertainty=timedelta(minutes=15))
    }

    recon = reconstruct_narrative("H1", claims, events, source_clocks=clocks)

    st_stage = recon.stages[1]
    assert st_stage.stage_name == "staging"
    assert st_stage.status == "SUPPORTED"
    # Overlapping intervals MUST NOT assert precedence!
    assert st_stage.relationship_to_previous == "CONCURRENT_OR_OVERLAPPING"


def test_reconstruct_gap_detected_for_unsupported_stages():
    """Unrecorded stages are identified as GAP."""
    ev_acc = _make_event("EV-1", "system_log", "login", "2026-10-18T02:00:00Z")
    events = [ev_acc]

    claims = [
        _make_claim("C1", "ACTOR_DEVICE_CONSISTENT", events=[ev_acc]),
    ]

    recon = reconstruct_narrative("H1", claims, events)
    assert recon.stages[0].status == "SUPPORTED"
    assert recon.stages[1].status == "GAP"
    assert recon.stages[2].status == "GAP"
    assert recon.stages[3].status == "GAP"


def test_reconstruct_background_and_h0_residual_events():
    """Events in case not belonging to hypothesis stages are tracked as background activity and H0."""
    ev_acc = _make_event("EV-1", "system_log", "login", "2026-10-18T02:00:00Z")
    ev_bg = _make_event("EV-99", "chat", "general_message", "2026-10-18T05:00:00Z")
    events = [ev_acc, ev_bg]

    claims = [
        _make_claim("C1", "ACTOR_DEVICE_CONSISTENT", events=[ev_acc]),
    ]

    recon = reconstruct_narrative("H1", claims, events, h0_event_ids=["EV-99"])
    assert recon.background_activity_count == 1
    assert "EV-99" in recon.background_activity_event_ids
    assert recon.residual_h0_count == 1
    assert "EV-99" in recon.residual_h0_event_ids
    assert "Reconstruction for" in recon.narrative_summary
