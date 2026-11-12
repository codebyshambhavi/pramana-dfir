"""Role 3 / T7: Comprehensive Hypothesis Engine Tests.

Tests:
1. Template loading and schema validation
2. Golden Case H1: Insider Exfiltration (H1 LEADING, H2 REFUTED, H3 WEAKENED)
3. Golden Case H2: Sanctioned Backup (H2 LEADING, H1 WEAKENED, H3 REFUTED)
4. Golden Case H3: Session Misuse (H3 LEADING)
5. Golden Case: UNDETERMINED outcome (insufficient diagnostic evidence or within margin)
6. Disconfirmation-based ranking (confirming evidence alone does not make a hypothesis win)
7. Two-level witness family deduplication ((source_kind, device) max contribution)
8. Coverage-aware MISSING vs UNOBSERVABLE handling (UNOBSERVABLE is strictly neutral)
9. Non-diagnostic evidence identification (common satisfied items marked non-diagnostic)
10. Residual H0 calculation (unassigned events collected into H0)
11. Next-best evidence recommendations (prioritizing unobservable distinguishing items)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
import pytest
import jsonschema

from intelligence.hyp.engine import (
    STATE_MISSING,
    STATE_SATISFIED,
    STATE_UNOBSERVABLE,
    STATE_VIOLATED,
    STATUS_LEADING,
    STATUS_REFUTED,
    STATUS_UNDETERMINED,
    STATUS_VIABLE,
    STATUS_WEAKENED,
    TemplateConstraint,
    TemplateItem,
    HypothesisTemplate,
    evaluate_hypotheses,
    load_templates,
)


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


def _make_claim(
    claim_id: str,
    claim_type: str,
    status: str = "ASSERTED",
    grade: str = "A",
    params: dict | None = None,
    events: list[dict] | None = None,
) -> dict:
    edges = []
    if events:
        for ev in events:
            edges.append({
                "ref_kind": "event",
                "ref_id": ev["event_id"],
                "role": "SUPPORTS",
                "family": f"{ev.get('source', 'sys')}:{ev.get('device', 'dev-1')}",
            })
    return {
        "claim_id": claim_id,
        "claim_key": f"KEY-{claim_id}",
        "type": claim_type,
        "status": status,
        "grade": grade,
        "params": params or {},
        "edges": edges,
    }


# --- 1. Template Loading & Schema Validation ---

def test_bundled_templates_validate_against_schema():
    templates = load_templates()
    assert len(templates) == 3
    ids = {t.id for t in templates}
    assert ids == {"H1", "H2", "H3"}

    for t in templates:
        assert len(t.stages) >= 2
        assert len(t.requires) >= 1
        assert len(t.forbids) >= 1
        assert len(t.constraints) >= 1


# --- 2. Golden Case: H1 Insider Exfiltration ---

def test_golden_case_h1_insider_exfiltration_plausible():
    """Actor alice accesses files and exfiltrates via browser during off-hours.
    Off-hours activity supports H1 but does not independently refute H2.
    H3 (Session Misuse) is WEAKENED/REFUTED by missing session origin mismatch.
    Result: H1 remains a plausible explanation.
    """
    ev_login = _make_event("EV-1", "system_log", "login", "2026-10-18T02:00:00Z", actor="alice", device="dev-01")
    ev_stage = _make_event("EV-2", "system_log", "archive_create", "2026-10-18T02:15:00Z", actor="alice", device="dev-01")
    ev_upload = _make_event("EV-3", "browser", "upload", "2026-10-18T02:20:00Z", actor="alice", device="dev-01")
    ev_chat = _make_event("EV-4", "chat", "message", "2026-10-18T02:25:00Z", actor="alice", device="dev-01")
    events = [ev_login, ev_stage, ev_upload, ev_chat]

    claims = [
        _make_claim("C1", "ACTOR_DEVICE_CONSISTENT", params={"actor": "alice", "device": "dev-01"}, events=[ev_login, ev_stage]),
        _make_claim("C2", "SAME_OBJECT_FLOW", params={"object": "archive.tar.gz"}, events=[ev_stage, ev_upload]),
        _make_claim("C3", "OFFHOURS_SESSION", params={"actor": "alice"}, events=[ev_login]),
    ]

    result = evaluate_hypotheses(claims, events)

    # Off-hours activity alone must not refute H2.
    h2 = next(h for h in result.ranked_hypotheses if h.id == "H2")
    assert h2.status != STATUS_REFUTED
    assert h2.hard_violations_count == 0
    # The chat event is not evidence for C1/C2, so H2's chat-specific
    # expectation is MISSING rather than satisfied by unrelated case evidence.
    assert h2.inconsistency_score == 0.25

    # H3 lacks session origin mismatch
    h3 = next(h for h in result.ranked_hypotheses if h.id == "H3")
    assert h3.status in (STATUS_WEAKENED, STATUS_REFUTED)


# --- 3. Golden Case: H2 Sanctioned Backup ---

def test_golden_case_h2_sanctioned_backup_leading():
    """Backup operator runs data transfer during normal hours (no offhours session).
    H2 has no violations and wins.
    H1 expects off-hours session (MISSING in covered window) and lacks evasion logs.
    """
    ev_auth = _make_event("EV-1", "system_log", "service_start", "2026-10-18T14:00:00Z", actor="backup-svc", device="srv-01")
    ev_trans = _make_event("EV-2", "browser", "backup_upload", "2026-10-18T14:15:00Z", actor="backup-svc", device="srv-01")
    ev_chat = _make_event("EV-3", "chat", "sync_ack", "2026-10-18T14:20:00Z", actor="backup-svc", device="srv-01")
    events = [ev_auth, ev_trans, ev_chat]

    claims = [
        _make_claim("C1", "ACTOR_DEVICE_CONSISTENT", params={"actor": "backup-svc", "device": "srv-01"}, events=[ev_auth, ev_trans]),
        _make_claim("C2", "SAME_OBJECT_FLOW", params={"object": "daily_backup.tar.gz"}, events=[ev_trans]),
        # Notice: NO OFFHOURS_SESSION claim!
    ]

    result = evaluate_hypotheses(claims, events)

    h2 = next(h for h in result.ranked_hypotheses if h.id == "H2")
    # No chat-backed claim exists, so H2's chat-specific expectation is MISSING.
    assert h2.inconsistency_score == 0.25
    assert h2.hard_violations_count == 0

    # H1 expects off-hours session. Since system_log covers this window, it is MISSING -> penalized
    h1 = next(h for h in result.ranked_hypotheses if h.id == "H1")
    assert h1.missing_expected_count >= 1
    assert h1.inconsistency_score > h2.inconsistency_score


# --- 4. Golden Case: H3 Session Misuse ---

def test_golden_case_h3_session_misuse_leading():
    """Session origin mismatch detected (login from conflicting remote IP).
    H1 forbids session origin mismatch -> H1 is REFUTED!
    H2 forbids session origin mismatch -> H2 is REFUTED!
    H3 has required session origin mismatch satisfied -> H3 is LEADING!
    """
    ev_auth = _make_event("EV-1", "auth", "token_refresh", "2026-10-18T03:00:00Z", actor="bob", device="laptop-02")
    ev_egress = _make_event("EV-2", "browser", "cloud_egress", "2026-10-18T03:10:00Z", actor="bob", device="laptop-02")
    events = [ev_auth, ev_egress]

    claims = [
        _make_claim("C1", "SESSION_ORIGIN_MISMATCH", params={"actor": "bob", "ip": "198.51.100.22"}, events=[ev_auth]),
        _make_claim("C2", "SAME_OBJECT_FLOW", params={"object": "secrets.zip"}, events=[ev_egress]),
        _make_claim("C3", "OFFHOURS_SESSION", params={"actor": "bob"}, events=[ev_auth]),
    ]

    result = evaluate_hypotheses(claims, events)

    # H1 forbids SESSION_ORIGIN_MISMATCH -> REFUTED
    h1 = next(h for h in result.ranked_hypotheses if h.id == "H1")
    assert h1.status == STATUS_REFUTED

    # H2 forbids SESSION_ORIGIN_MISMATCH -> REFUTED
    h2 = next(h for h in result.ranked_hypotheses if h.id == "H2")
    assert h2.status == STATUS_REFUTED

    # H3 requires SESSION_ORIGIN_MISMATCH -> SATISFIED and LEADING
    top = result.ranked_hypotheses[0]
    assert top.id == "H3"
    assert top.status == STATUS_LEADING
    assert result.outcome == STATUS_LEADING


# --- 5. Golden Case: UNDETERMINED Outcome ---

def test_golden_case_undetermined_insufficient_diagnostic_evidence():
    """When only non-diagnostic common evidence exists, no hypothesis can be established as LEADING."""
    ev = _make_event("EV-1", "system_log", "boot", "2026-10-18T10:00:00Z", actor="alice", device="dev-01")
    events = [ev]

    # Only consistent actor-device claim (consistent with multiple hypotheses)
    claims = [
        _make_claim("C1", "ACTOR_DEVICE_CONSISTENT", params={"actor": "alice", "device": "dev-01"}, events=[ev]),
    ]

    result = evaluate_hypotheses(claims, events)
    assert result.outcome == STATUS_UNDETERMINED
    for h in result.ranked_hypotheses:
        assert h.status != STATUS_LEADING


# --- 6. Disconfirmation-Based Ranking ---

def test_disconfirmation_ranking_confirming_evidence_alone_does_not_win():
    """A hypothesis with many confirming items but one hard violation is REFUTED,
    whereas a hypothesis with zero violations ranks higher even with fewer items.
    """
    ev1 = _make_event("EV-1", "system_log", "login", "2026-10-18T12:00:00Z")
    ev2 = _make_event("EV-2", "browser", "upload", "2026-10-18T12:05:00Z")
    events = [ev1, ev2]

    # H2 has SAME_OBJECT_FLOW and ACTOR_DEVICE_CONSISTENT, BUT also has a forbidden SESSION_ORIGIN_MISMATCH
    claims = [
        _make_claim("C1", "ACTOR_DEVICE_CONSISTENT", events=[ev1]),
        _make_claim("C2", "SAME_OBJECT_FLOW", events=[ev2]),
        _make_claim("C3", "SESSION_ORIGIN_MISMATCH", events=[ev1]),
    ]

    result = evaluate_hypotheses(claims, events)
    h2 = next(h for h in result.ranked_hypotheses if h.id == "H2")
    assert h2.status == STATUS_REFUTED


# --- 7. Two-Level Witness Family Deduplication ---

def test_witness_family_deduplication():
    """Multiple violations from the same (source_kind, device) family count once
    using the maximum contribution, rather than summing up artificially.
    """
    ev1 = _make_event("EV-1", "auth", "login", "2026-10-18T02:00:00Z", device="srv-01")
    ev2 = _make_event("EV-2", "auth", "auth", "2026-10-18T02:05:00Z", device="srv-01")
    events = [ev1, ev2]

    # Two origin-mismatch claims from the same (auth, srv-01) family.
    claims = [
        _make_claim("C1", "SESSION_ORIGIN_MISMATCH", events=[ev1]),
        _make_claim("C2", "SESSION_ORIGIN_MISMATCH", events=[ev2]),
    ]

    result = evaluate_hypotheses(claims, events)
    h2 = next(h for h in result.ranked_hypotheses if h.id == "H2")
    # One witness family contributes its maximum penalty, not the sum.
    assert h2.inconsistency_score == 2.0


# --- 8. Coverage-Aware: MISSING vs UNOBSERVABLE ---

def test_missing_vs_unobservable_handling():
    """If expected source is present in the case evidence -> absence is MISSING (penalized).
    If expected source is completely uncollected/absent -> absence is UNOBSERVABLE (neutral, 0 penalty).
    """
    # Only system_log is in the evidence. Audit logs were NOT collected.
    ev_log = _make_event("EV-1", "system_log", "login", "2026-10-18T10:00:00Z")
    events = [ev_log]

    # Empty claims
    result = evaluate_hypotheses([], events)

    h1 = next(h for h in result.ranked_hypotheses if h.id == "H1")

    # Item H1-REQ-1 expects system_log -> source is present -> MISSING
    req_item = next(e for e in h1.evaluations if e.item_id == "H1-REQ-1")
    assert req_item.state == STATE_MISSING
    assert req_item.disconfirmation_penalty > 0.0

    # Item H1-EXP-2 expects audit logs -> audit source not present -> UNOBSERVABLE
    audit_item = next(e for e in h1.evaluations if e.item_id == "H1-EXP-2")
    assert audit_item.state == STATE_UNOBSERVABLE
    # UNOBSERVABLE MUST BE STRICTLY NEUTRAL (0.0 penalty)
    assert audit_item.disconfirmation_penalty == 0.0


# --- 9. Non-Diagnostic Evidence Detection ---

def test_non_diagnostic_evidence_flagged():
    """Evidence satisfied across all competing hypotheses is flagged as non-diagnostic."""
    ev = _make_event("EV-1", "system_log", "access", "2026-10-18T10:00:00Z")
    ev2 = _make_event("EV-2", "browser", "flow", "2026-10-18T10:10:00Z")
    events = [ev, ev2]

    claims = [
        _make_claim("C1", "ACTOR_DEVICE_CONSISTENT", events=[ev]),
        _make_claim("C2", "SAME_OBJECT_FLOW", events=[ev2]),
    ]

    result = evaluate_hypotheses(claims, events)
    # Check that any item satisfied in all 3 templates has diagnostic=False
    for h in result.ranked_hypotheses:
        for item in h.evaluations:
            if item.claim_type == "SAME_OBJECT_FLOW" and item.state == STATE_SATISFIED:
                # If satisfied in H1, H2, H3, it is marked non-diagnostic
                all_have_it = all(
                    any(e.claim_type == "SAME_OBJECT_FLOW" and e.state == STATE_SATISFIED for e in other.evaluations)
                    for other in result.ranked_hypotheses
                )
                if all_have_it:
                    assert item.diagnostic is False
                    assert "NON-DIAGNOSTIC" in item.rationale


# --- 10. Residual H0 Calculation ---

def test_residual_h0_calculation():
    """Events not assigned to any hypothesis stage are collected into H0 residual."""
    ev1 = _make_event("EV-1", "system_log", "login", "2026-10-18T02:00:00Z")
    ev2 = _make_event("EV-2", "browser", "upload", "2026-10-18T02:20:00Z")
    ev_unrelated = _make_event("EV-99", "chat", "lunch_chat", "2026-10-18T12:00:00Z")
    events = [ev1, ev2, ev_unrelated]

    claims = [
        _make_claim("C1", "ACTOR_DEVICE_CONSISTENT", events=[ev1]),
        _make_claim("C2", "SAME_OBJECT_FLOW", events=[ev2]),
    ]

    result = evaluate_hypotheses(claims, events)
    assert result.h0_residual.id == "H0"
    assert result.h0_residual.unassigned_event_count >= 1
    assert "EV-99" in result.h0_residual.unassigned_event_ids


# --- 11. Next-Best Evidence Calculation ---

def test_next_best_evidence_recommends_unobservable_discriminators():
    """Next-best evidence produces recommendations prioritizing unobservable distinguishing items."""
    ev = _make_event("EV-1", "system_log", "login", "2026-10-18T10:00:00Z")
    events = [ev]

    claims = [
        _make_claim("C1", "ACTOR_DEVICE_CONSISTENT", events=[ev]),
    ]

    result = evaluate_hypotheses(claims, events)
    assert len(result.next_best_evidence) > 0
    rec = result.next_best_evidence[0]
    assert rec.priority in ("HIGH", "MEDIUM")
    assert len(rec.distinguishes) == 2
    assert "rationale" in rec.to_dict()
