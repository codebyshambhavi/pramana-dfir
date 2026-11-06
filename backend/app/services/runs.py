"""Role 3 / T8: Immutable Analysis Runs & Run Diffing Service.

Provides deterministic write-once analysis run creation, verification,
reproducible retrieval, and semantic run diffing matching claims by claim_key.
"""
from __future__ import annotations

import logging
from typing import Any, Sequence
from datetime import datetime

from sqlalchemy.orm import Session

from app.db.claims import compute_claim_key
from app.db.models import (
    EVIDENCE_ACTIVE,
    AnalysisRun,
    Case,
    Claim,
    ClaimEdge,
    EventModel,
    Evidence,
    HypothesisEval,
    SourceCoverage,
)
from app.db.runs import create_analysis_run, manifest_evidence
from intelligence.claims import generate_claims
from intelligence.hyp.engine import evaluate_hypotheses
from intelligence.hyp.reconstruct import reconstruct_narrative

logger = logging.getLogger("pramana.services.runs")


def execute_analysis_run(
    db: Session,
    case_id: str,
    *,
    engine_version: str = "pramana-engine@1.0.0",
    assumptions: dict[str, Any] | None = None,
    parent_run_id: str | None = None,
) -> dict[str, Any]:
    """Execute complete T5 correlation, T6 claims, and T7 hypothesis evaluation,
    persisting an immutable write-once AnalysisRun.
    """
    case = db.get(Case, case_id)
    if not case:
        raise LookupError(f"Case '{case_id}' not found")

    case_assumptions = assumptions or {"case_timezone": "UTC"}

    # 1. Manifest ACTIVE evidence
    manifest = manifest_evidence(db, case_id)
    if not manifest:
        raise ValueError(f"Case '{case_id}' has no ACTIVE evidence to analyze")

    active_ev_ids = {e["evidence_id"] for e in manifest}

    # 2. Load stored case events only for active manifest evidence
    events = (
        db.query(EventModel)
        .filter(EventModel.case_id == case_id, EventModel.evidence_id.in_(list(active_ev_ids)))
        .all()
    )
    events_payload = [e.to_dict() for e in events]

    # 3. Generate T5 candidate relationships and T6 claims
    claim_specs = generate_claims(events_payload)

    # 4. Evaluate T7 competing hypotheses & residual H0
    hyp_result = evaluate_hypotheses(
        claims=claim_specs,
        events=events_payload,
        assumptions=case_assumptions,
    )

    # 5. Persist write-once analysis run with ranking_hash
    run = create_analysis_run(
        db,
        case_id=case_id,
        engine_version=engine_version,
        assumptions=case_assumptions,
        claims=claim_specs,
        parent_run_id=parent_run_id,
        ranking_hash=hyp_result.ranking_hash,
    )

    # 6. Reconstruct narrative for leading/top hypothesis
    top_hyp = hyp_result.ranked_hypotheses[0] if hyp_result.ranked_hypotheses else None
    reconstruction = None
    if top_hyp:
        reconstruction = reconstruct_narrative(
            hypothesis=top_hyp,
            claims=claim_specs,
            events=events_payload,
            h0_event_ids=hyp_result.h0_residual.unassigned_event_ids,
        )

    return {
        "run_id": run.run_id,
        "case_id": case_id,
        "parent_run_id": parent_run_id,
        "engine_version": run.engine_version,
        "assumptions_hash": run.assumptions_hash,
        "manifest": run.manifest,
        "claims_count": len(run.claims),
        "ranking_hash": run.ranking_hash,
        "ranked_hypotheses": [h.to_dict() for h in hyp_result.ranked_hypotheses],
        "h0_residual": hyp_result.h0_residual.to_dict(),
        "reconstruction": reconstruction.to_dict() if reconstruction else None,
        "next_best_evidence": [n.to_dict() for n in hyp_result.next_best_evidence],
        "outcome": hyp_result.outcome,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }


def get_run_details(db: Session, run_id: str) -> dict[str, Any]:
    """Retrieve a complete, reproducible immutable run and verify its integrity."""
    run = db.get(AnalysisRun, run_id)
    if not run:
        raise LookupError(f"AnalysisRun '{run_id}' not found")

    # Verify validity of input evidence:
    # Check if any evidence in manifest has been QUARANTINED or REMOVED
    manifest_evidence_list = run.manifest.get("evidence", [])
    invalidating_reasons: list[str] = []
    is_valid = True

    for ev_item in manifest_evidence_list:
        ev_id = ev_item.get("evidence_id")
        ev = db.get(Evidence, ev_id)
        if not ev:
            is_valid = False
            invalidating_reasons.append(f"Evidence '{ev_id}' no longer exists in database")
        elif ev.status != EVIDENCE_ACTIVE:
            is_valid = False
            invalidating_reasons.append(
                f"Evidence '{ev_id}' status is now {ev.status} (verify_state: {ev.verify_state})"
            )

    validity_status = "VALID" if is_valid else "INVALIDATED"

    # Load stored claims for this run
    claims = db.query(Claim).filter(Claim.run_id == run_id).order_by(Claim.claim_id.asc()).all()
    claims_payload = [c.to_dict() for c in claims]

    # Load stored events for the run's manifest evidence
    ev_ids = [e["evidence_id"] for e in manifest_evidence_list]
    events = (
        db.query(EventModel)
        .filter(EventModel.case_id == run.case_id, EventModel.evidence_id.in_(ev_ids))
        .all()
    )
    events_payload = [e.to_dict() for e in events]

    # Deterministically evaluate hypotheses from persisted claims and events
    assumptions = run.manifest.get("assumptions", {})
    hyp_result = evaluate_hypotheses(
        claims=claims_payload,
        events=events_payload,
        assumptions=assumptions,
    )

    # Narrative reconstruction for leading/top hypothesis
    top_hyp = hyp_result.ranked_hypotheses[0] if hyp_result.ranked_hypotheses else None
    reconstruction = None
    if top_hyp:
        reconstruction = reconstruct_narrative(
            hypothesis=top_hyp,
            claims=claims_payload,
            events=events_payload,
            h0_event_ids=hyp_result.h0_residual.unassigned_event_ids,
        )

    # Check that computed ranking_hash matches stored ranking_hash
    ranking_hash_match = (hyp_result.ranking_hash == run.ranking_hash)

    return {
        "run_id": run.run_id,
        "case_id": run.case_id,
        "parent_run_id": run.parent_run_id,
        "engine_version": run.engine_version,
        "assumptions_hash": run.assumptions_hash,
        "manifest": run.manifest,
        "validity": validity_status,
        "is_valid": is_valid,
        "invalidation_reasons": invalidating_reasons,
        "ranking_hash": run.ranking_hash,
        "ranking_hash_verified": ranking_hash_match,
        "claims_count": len(claims),
        "claims": claims_payload,
        "ranked_hypotheses": [h.to_dict() for h in hyp_result.ranked_hypotheses],
        "h0_residual": hyp_result.h0_residual.to_dict(),
        "reconstruction": reconstruction.to_dict() if reconstruction else None,
        "next_best_evidence": [n.to_dict() for n in hyp_result.next_best_evidence],
        "outcome": hyp_result.outcome,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }


def diff_runs(db: Session, run_a_id: str, run_b_id: str) -> dict[str, Any]:
    """Compare two immutable runs matching claims by claim_key and explaining
    root cause of conclusion changes.
    """
    run_a = db.get(AnalysisRun, run_a_id)
    if not run_a:
        raise LookupError(f"AnalysisRun '{run_a_id}' not found")
    run_b = db.get(AnalysisRun, run_b_id)
    if not run_b:
        raise LookupError(f"AnalysisRun '{run_b_id}' not found")

    det_a = get_run_details(db, run_a_id)
    det_b = get_run_details(db, run_b_id)

    # 1. Manifest Diff
    manifest_a = {e["evidence_id"]: e["sha256"] for e in det_a["manifest"].get("evidence", [])}
    manifest_b = {e["evidence_id"]: e["sha256"] for e in det_b["manifest"].get("evidence", [])}

    evidence_added = [
        {"evidence_id": eid, "sha256": manifest_b[eid]}
        for eid in sorted(set(manifest_b) - set(manifest_a))
    ]
    evidence_removed = [
        {"evidence_id": eid, "sha256": manifest_a[eid]}
        for eid in sorted(set(manifest_a) - set(manifest_b))
    ]

    # 2. Claims Diff Matching by claim_key!
    claims_a_by_key = {c["claim_key"]: c for c in det_a["claims"]}
    claims_b_by_key = {c["claim_key"]: c for c in det_b["claims"]}

    keys_a = set(claims_a_by_key.keys())
    keys_b = set(claims_b_by_key.keys())

    added_claim_keys = sorted(keys_b - keys_a)
    removed_claim_keys = sorted(keys_a - keys_b)
    common_claim_keys = sorted(keys_a & keys_b)

    modified_claims = []
    unchanged_count = 0

    for k in common_claim_keys:
        ca = claims_a_by_key[k]
        cb = claims_b_by_key[k]
        if ca["status"] != cb["status"] or ca["grade"] != cb["grade"]:
            modified_claims.append({
                "claim_key": k,
                "type": ca["type"],
                "params": ca["params"],
                "old_status": ca["status"],
                "new_status": cb["status"],
                "old_grade": ca["grade"],
                "new_grade": cb["grade"],
            })
        else:
            unchanged_count += 1

    # 3. Hypothesis Ranking Diff
    hyps_a = {h["id"]: h for h in det_a["ranked_hypotheses"]}
    hyps_b = {h["id"]: h for h in det_b["ranked_hypotheses"]}

    hypothesis_diffs = []
    root_cause_notes = []

    for hid in sorted(set(hyps_a) | set(hyps_b)):
        ha = hyps_a.get(hid)
        hb = hyps_b.get(hid)
        if ha and hb:
            rank_changed = ha["rank"] != hb["rank"]
            status_changed = ha["status"] != hb["status"]
            score_delta = round(hb["inconsistency_score"] - ha["inconsistency_score"], 3)

            diff_entry = {
                "hypothesis_id": hid,
                "name": ha["name"],
                "old_rank": ha["rank"],
                "new_rank": hb["rank"],
                "old_status": ha["status"],
                "new_status": hb["status"],
                "old_score": ha["inconsistency_score"],
                "new_score": hb["inconsistency_score"],
                "score_delta": score_delta,
                "changed": rank_changed or status_changed or score_delta != 0.0,
            }
            hypothesis_diffs.append(diff_entry)

            if status_changed:
                root_cause_notes.append(
                    f"{hid} ({ha['name']}) transitioned from {ha['status']} to {hb['status']}."
                )
        elif ha and not hb:
            hypothesis_diffs.append({"hypothesis_id": hid, "transition": "DROPPED"})
        elif hb and not ha:
            hypothesis_diffs.append({"hypothesis_id": hid, "transition": "INTRODUCED"})

    if evidence_removed:
        rem_ids = [e["evidence_id"] for e in evidence_removed]
        root_cause_notes.append(
            f"Input evidence items removed/quarantined in run B: {rem_ids}. "
            f"This caused {len(removed_claim_keys)} claim(s) to be invalidated."
        )

    # 4. Reconstruction Diff
    recon_a = det_a.get("reconstruction")
    recon_b = det_b.get("reconstruction")
    stage_changes = []
    if recon_a and recon_b:
        st_a = {s["stage_name"]: s for s in recon_a.get("stages", [])}
        st_b = {s["stage_name"]: s for s in recon_b.get("stages", [])}
        for st_name in sorted(set(st_a) | set(st_b)):
            sa = st_a.get(st_name)
            sb = st_b.get(st_name)
            if sa and sb and sa["status"] != sb["status"]:
                stage_changes.append({
                    "stage_name": st_name,
                    "old_status": sa["status"],
                    "new_status": sb["status"],
                })

    return {
        "run_a_id": run_a_id,
        "run_b_id": run_b_id,
        "evidence_diff": {
            "added": evidence_added,
            "removed": evidence_removed,
        },
        "claims_diff": {
            "added_count": len(added_claim_keys),
            "added_claims": [claims_b_by_key[k] for k in added_claim_keys],
            "removed_count": len(removed_claim_keys),
            "removed_claims": [claims_a_by_key[k] for k in removed_claim_keys],
            "modified_count": len(modified_claims),
            "modified_claims": modified_claims,
            "unchanged_count": unchanged_count,
        },
        "hypothesis_diffs": hypothesis_diffs,
        "stage_changes": stage_changes,
        "root_cause_analysis": " ".join(root_cause_notes) if root_cause_notes else "No major hypothesis status transitions.",
    }
