"""Role 3 / Item 2: ASSUMED claims must never count as evidence.

Verifies:
1. An ASSUMED claim matching a required item does not satisfy it.
2. An ASSUMED claim matching an expected item does not satisfy it.
3. An ASSUMED claim matching a forbidden item does not trigger violation.
4. Mixed ASSUMED and ASSERTED claims: only ASSERTED counts as evidence.
5. ASSUMED claims sharing a witness family do not alter witness family deduplication.
6. Removing an ASSUMED claim from the input does not change the evidence-derived score or ranking.
"""
from __future__ import annotations

import copy
from datetime import datetime
import pytest

from intelligence.hyp.engine import (
    STATE_MISSING,
    STATE_SATISFIED,
    STATE_UNOBSERVABLE,
    STATE_VIOLATED,
    evaluate_hypotheses,
    load_templates,
)

BASE_EVENTS = [
    {
        "event_id": "EV-1",
        "timestamp": "2026-10-18T02:00:00Z",
        "action": "login",
        "actor": "mira",
        "device": "dev-01",
        "source": "auth_log.csv",
    },
    {
        "event_id": "EV-2",
        "timestamp": "2026-10-18T02:30:00Z",
        "action": "logout",
        "actor": "mira",
        "device": "dev-01",
        "source": "auth_log.csv",
    },
]


def test_assumed_claim_matching_required_item_does_not_satisfy():
    """An ASSUMED claim matching a required item must NOT satisfy it."""
    # H1 requires ACTOR_DEVICE_CONSISTENT for initial_access stage.
    # Provide it only as an ASSUMED claim.
    claims = [
        {
            "claim_id": "CLAIM-ASSUMED-REQ",
            "type": "ACTOR_DEVICE_CONSISTENT",
            "params": {"actor": "mira", "device": "dev-01"},
            "status": "ASSUMED",
            "grade": "B",
        }
    ]

    result = evaluate_hypotheses(claims=claims, events=BASE_EVENTS)
    h1 = next(h for h in result.ranked_hypotheses if h.id == "H1")
    req_item = next(e for e in h1.evaluations if e.category == "requires" and e.claim_type == "ACTOR_DEVICE_CONSISTENT")

    # Must NOT be SATISFIED
    assert req_item.state in (STATE_MISSING, STATE_UNOBSERVABLE)
    assert req_item.matched_claim_ids == []
    assert req_item.assumed_claim_ids == ["CLAIM-ASSUMED-REQ"]
    # Disconfirmation penalty was not reduced to 0
    if req_item.state == STATE_MISSING:
        assert req_item.disconfirmation_penalty > 0.0


def test_assumed_claim_matching_expected_item_does_not_satisfy():
    """An ASSUMED claim matching an expected item must NOT satisfy it."""
    # H1 expects OFFHOURS_SESSION for staging stage. Provide as ASSUMED.
    claims = [
        {
            "claim_id": "CLAIM-ASSUMED-EXP",
            "type": "OFFHOURS_SESSION",
            "params": {"actor": "mira"},
            "status": "ASSUMED",
            "grade": "B",
        }
    ]

    result = evaluate_hypotheses(claims=claims, events=BASE_EVENTS)
    h1 = next(h for h in result.ranked_hypotheses if h.id == "H1")
    exp_item = next(e for e in h1.evaluations if e.category == "expects" and e.claim_type == "OFFHOURS_SESSION")

    assert exp_item.state in (STATE_MISSING, STATE_UNOBSERVABLE)
    assert exp_item.matched_claim_ids == []
    assert exp_item.assumed_claim_ids == ["CLAIM-ASSUMED-EXP"]


def test_assumed_claim_matching_forbidden_item_does_not_violate():
    """An ASSUMED claim matching a forbidden item must NOT trigger a violation."""
    # H1 forbids SESSION_ORIGIN_MISMATCH. Provide as ASSUMED claim.
    claims = [
        {
            "claim_id": "CLAIM-ASSUMED-FORBID",
            "type": "SESSION_ORIGIN_MISMATCH",
            "params": {"actor": "mira"},
            "status": "ASSUMED",
            "grade": "B",
        }
    ]

    result = evaluate_hypotheses(claims=claims, events=BASE_EVENTS)
    h1 = next(h for h in result.ranked_hypotheses if h.id == "H1")
    forbid_item = next(e for e in h1.evaluations if e.category == "forbids" and e.claim_type == "SESSION_ORIGIN_MISMATCH")

    # Must NOT be VIOLATED because an assumption cannot establish a factual contradiction
    assert forbid_item.state != STATE_VIOLATED
    assert forbid_item.disconfirmation_penalty == 0.0
    assert forbid_item.matched_claim_ids == []
    assert forbid_item.assumed_claim_ids == ["CLAIM-ASSUMED-FORBID"]


def test_mixed_assumed_and_asserted_claims():
    """When both ASSERTED and ASSUMED claims match, only ASSERTED counts as evidence."""
    system_event = {
        **BASE_EVENTS[0],
        "event_id": "EV-SYSTEM",
        "source": "system_log",
    }
    claims = [
        {
            "claim_id": "CLAIM-REAL-1",
            "type": "ACTOR_DEVICE_CONSISTENT",
            "params": {"actor": "mira", "device": "dev-01"},
            "status": "ASSERTED",
            "grade": "A",
            "edges": [{"ref_kind": "event", "ref_id": "EV-SYSTEM", "role": "SUPPORTS"}],
        },
        {
            "claim_id": "CLAIM-ASSUMED-1",
            "type": "ACTOR_DEVICE_CONSISTENT",
            "params": {"actor": "mira", "device": "dev-01"},
            "status": "ASSUMED",
            "grade": "B",
        },
    ]

    result = evaluate_hypotheses(claims=claims, events=[*BASE_EVENTS, system_event])
    h1 = next(h for h in result.ranked_hypotheses if h.id == "H1")
    req_item = next(e for e in h1.evaluations if e.category == "requires" and e.claim_type == "ACTOR_DEVICE_CONSISTENT")

    assert req_item.state == STATE_SATISFIED
    assert req_item.matched_claim_ids == ["CLAIM-REAL-1"]
    assert req_item.assumed_claim_ids == ["CLAIM-ASSUMED-1"]
    # Only the real claim is in supporting_claim_ids
    assert "CLAIM-REAL-1" in h1.supporting_claim_ids
    assert "CLAIM-ASSUMED-1" not in h1.supporting_claim_ids


def test_assumed_claim_sharing_witness_family_does_not_affect_dedup():
    """An ASSUMED claim cannot participate in or distort witness-family deduplication."""
    # Create an evidence claim with REFUTED status (causes violation penalty)
    # and an ASSUMED claim in the same family.
    claims_without_assumed = [
        {
            "claim_id": "CLAIM-REFUTED",
            "type": "ACTOR_DEVICE_CONSISTENT",
            "params": {"actor": "mira", "device": "dev-01"},
            "status": "REFUTED",
            "grade": "F",
            "edges": [{"ref_kind": "event", "ref_id": "EV-1", "role": "SUPPORTS"}],
        }
    ]
    claims_with_assumed = copy.deepcopy(claims_without_assumed) + [
        {
            "claim_id": "CLAIM-ASSUMED",
            "type": "ACTOR_DEVICE_CONSISTENT",
            "params": {"actor": "mira", "device": "dev-01"},
            "status": "ASSUMED",
            "grade": "B",
        }
    ]

    res_without = evaluate_hypotheses(claims=claims_without_assumed, events=BASE_EVENTS)
    res_with = evaluate_hypotheses(claims=claims_with_assumed, events=BASE_EVENTS)

    h1_without = next(h for h in res_without.ranked_hypotheses if h.id == "H1")
    h1_with = next(h for h in res_with.ranked_hypotheses if h.id == "H1")

    assert h1_without.inconsistency_score == h1_with.inconsistency_score
    assert res_without.ranking_hash == res_with.ranking_hash


def test_assumed_claims_cannot_improve_hypothesis_ranking():
    """Removing an ASSUMED claim must not change score or make hypothesis appear better supported."""
    claims = [
        {
            "claim_id": "REAL-1",
            "type": "ACTOR_DEVICE_CONSISTENT",
            "params": {"actor": "mira", "device": "dev-01"},
            "status": "ASSERTED",
            "grade": "A",
            "edges": [{"ref_kind": "event", "ref_id": "EV-1", "role": "SUPPORTS"}],
        },
        # Arbitrary assumptions
        {
            "claim_id": "ASSUMED-EXFIL",
            "type": "ARCHIVE_CREATED",
            "params": {"object": "secret.tar.gz"},
            "status": "ASSUMED",
            "grade": "C",
        },
        {
            "claim_id": "ASSUMED-BACKUP",
            "type": "OFF_HOURS_BURST",
            "params": {"service": "scheduled_backup"},
            "status": "ASSUMED",
            "grade": "C",
        },
    ]

    res_full = evaluate_hypotheses(claims=claims, events=BASE_EVENTS)

    # Filter out all ASSUMED claims
    evidence_only_claims = [c for c in claims if c["status"] != "ASSUMED"]
    res_evidence_only = evaluate_hypotheses(claims=evidence_only_claims, events=BASE_EVENTS)

    # Inconsistency scores across all hypotheses must be IDENTICAL
    for h_full, h_ev in zip(res_full.ranked_hypotheses, res_evidence_only.ranked_hypotheses):
        assert h_full.id == h_ev.id
        assert h_full.inconsistency_score == h_ev.inconsistency_score
        assert h_full.status == h_ev.status

    assert res_full.ranking_hash == res_evidence_only.ranking_hash
    assert res_full.outcome == res_evidence_only.outcome
    assert sorted(res_full.h0_residual.unassigned_event_ids) == sorted(res_evidence_only.h0_residual.unassigned_event_ids)
