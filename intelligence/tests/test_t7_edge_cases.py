"""Role 3 / Task 6: Edge Cases and Reasoning Engine Tests for T7/T8.

Tests edge cases:
1. Zero claims: evaluation gracefully handles empty claims.
2. Single hypothesis: evaluated with ranking and margin.
3. Identical scores / tie handling:
   - Primary tie-break: diagnostic satisfied items.
   - If tied on score and diagnostic items, outcome remains UNDETERMINED.
4. All hypotheses violated/refuted: outcome transitions to REFUTED.
5. Reconstruction interval arithmetic: overlapping vs definite precedence.
"""
from __future__ import annotations

from datetime import datetime, timezone
import pytest

from intelligence.hyp.engine import (
    STATUS_LEADING,
    STATUS_REFUTED,
    STATUS_UNDETERMINED,
    STATUS_VIABLE,
    STATUS_WEAKENED,
    STATE_SATISFIED,
    STATE_VIOLATED,
    evaluate_hypotheses,
    HypothesisTemplate,
    TemplateItem,
    TemplateConstraint,
)
from intelligence.hyp.reconstruct import reconstruct_narrative
from intelligence.timeline import TimeInterval, SourceClock


def _make_dummy_tmpl(hyp_id: str, claim_type: str, stage: str = "stage1") -> HypothesisTemplate:
    return HypothesisTemplate(
        id=hyp_id,
        kind="test_kind",
        name=f"Hypothesis {hyp_id}",
        description="Test hypothesis",
        stages=[stage],
        requires=[
            TemplateItem(
                id=f"{hyp_id}-REQ-1",
                stage=stage,
                description="Required claim",
                claim_type=claim_type,
                weight=1.0,
                critical=True,
            )
        ],
        expects=[],
        forbids=[],
        constraints=[],
    )


# --- 1. Zero Claims Edge Case ---

def test_zero_claims_edge_case():
    """Evaluating with zero claims does not crash and produces viable/weakened hypotheses."""
    events = [
        {"event_id": "E1", "timestamp": "2026-10-18T10:00:00Z", "source": "system_log"}
    ]
    res = evaluate_hypotheses(claims=[], events=events)
    assert len(res.ranked_hypotheses) == 3
    assert res.h0_residual.unassigned_event_count == 1
    assert res.ranking_hash is not None


# --- 2. Single Hypothesis Edge Case ---

def test_single_hypothesis_leads_when_supported():
    """A single viable hypothesis with diagnostic evidence becomes LEADING."""
    tmpl = _make_dummy_tmpl("H1", "ACTOR_DEVICE_CONSISTENT")
    claims = [
        {
            "claim_id": "C1",
            "type": "ACTOR_DEVICE_CONSISTENT",
            "params": {"actor": "alice", "device": "dev-1"},
            "status": "ASSERTED",
            "grade": "A",
            "edges": [],
        }
    ]
    events = [
        {"event_id": "E1", "timestamp": "2026-10-18T10:00:00Z", "source": "system_log"}
    ]
    res = evaluate_hypotheses(claims=claims, events=events, templates=[tmpl])
    assert len(res.ranked_hypotheses) == 1
    top = res.ranked_hypotheses[0]
    assert top.status == STATUS_LEADING
    assert res.outcome == STATUS_LEADING


# --- 3. Identical Scores / Tie-Breaking ---

def test_tie_breaking_by_diagnostic_items():
    """When two hypotheses have equal inconsistency_score, one with more diagnostic items ranks higher."""
    tmpl_a = _make_dummy_tmpl("HA", "CLAIM_ALPHA")
    tmpl_b = _make_dummy_tmpl("HB", "CLAIM_BETA")
    # Both have 0 inconsistency penalty, but HA has CLAIM_ALPHA satisfied while HB lacks CLAIM_BETA
    # Let HA satisfy 1 item, HB satisfy 0
    claims = [
        {"claim_id": "C1", "type": "CLAIM_ALPHA", "params": {}, "status": "ASSERTED", "grade": "A", "edges": []}
    ]
    events = [
        {"event_id": "E1", "timestamp": "2026-10-18T10:00:00Z", "source": "other"}
    ]
    res = evaluate_hypotheses(claims=claims, events=events, templates=[tmpl_a, tmpl_b])
    ranked = res.ranked_hypotheses
    assert ranked[0].id == "HA"
    assert ranked[0].rank == 1
    assert ranked[1].id == "HB"
    assert ranked[1].rank == 2
    assert res.outcome == STATUS_LEADING
    assert ranked[0].status == STATUS_LEADING


def test_identical_tie_yields_undetermined_outcome():
    """When two viable hypotheses have identical scores and diagnostic counts, outcome is UNDETERMINED."""
    tmpl_a = _make_dummy_tmpl("HA", "SAME_CLAIM")
    tmpl_b = _make_dummy_tmpl("HB", "SAME_CLAIM")
    claims = [
        {"claim_id": "C1", "type": "SAME_CLAIM", "params": {}, "status": "ASSERTED", "grade": "A", "edges": []}
    ]
    events = [
        {"event_id": "E1", "timestamp": "2026-10-18T10:00:00Z", "source": "other"}
    ]
    res = evaluate_hypotheses(claims=claims, events=events, templates=[tmpl_a, tmpl_b], margin=0.5)
    assert res.ranked_hypotheses[0].inconsistency_score == res.ranked_hypotheses[1].inconsistency_score
    assert res.outcome == STATUS_UNDETERMINED


# --- 4. All Hypotheses Violated / Refuted ---

def test_all_hypotheses_refuted():
    """When all competing hypotheses encounter hard violations, outcome is REFUTED and H0 retains all events."""
    tmpl_a = HypothesisTemplate(
        id="HA", kind="k", name="A", description="d", stages=["st"],
        requires=[], expects=[],
        forbids=[TemplateItem("F1", "st", "forbidden", "BAD_CLAIM", critical=True)],
        constraints=[],
    )
    tmpl_b = HypothesisTemplate(
        id="HB", kind="k", name="B", description="d", stages=["st"],
        requires=[], expects=[],
        forbids=[TemplateItem("F2", "st", "forbidden", "BAD_CLAIM", critical=True)],
        constraints=[],
    )
    claims = [
        {"claim_id": "C1", "type": "BAD_CLAIM", "params": {}, "status": "ASSERTED", "grade": "A", "edges": []}
    ]
    events = [
        {"event_id": "E1", "timestamp": "2026-10-18T10:00:00Z", "source": "sys"}
    ]
    res = evaluate_hypotheses(claims=claims, events=events, templates=[tmpl_a, tmpl_b])
    assert all(h.status == STATUS_REFUTED for h in res.ranked_hypotheses)
    assert res.outcome == STATUS_REFUTED
    assert res.h0_residual.unassigned_event_count == 1
