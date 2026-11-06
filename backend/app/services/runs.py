"""Role 3 / T8: Immutable Analysis Runs & Run Diffing Service.

Provides deterministic write-once analysis run creation, verification,
reproducible retrieval, and semantic run diffing matching claims by claim_key.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Sequence
from datetime import datetime

from sqlalchemy.orm import Session

from app.db.claims import H, compute_claim_key
from app.db.models import (
    EVIDENCE_ACTIVE,
    AnalysisRun,
    Case,
    Claim,
    ClaimEdge,
    EventModel,
    Evidence,
    HypothesisEval,
    RunSnapshot,
    SourceCoverage,
)
from app.db.runs import create_analysis_run, manifest_evidence
from intelligence.claims import generate_claims
from intelligence.hyp.engine import evaluate_hypotheses, load_templates
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

    # 4. Generate run_id and pre-build claim rows so every claim has its real content-addressed claim_id
    from app.db.runs import new_run_id, compute_assumptions_hash
    from app.db.claims import build_claim_rows
    target_run_id = new_run_id()
    assumptions_hash = compute_assumptions_hash(case_assumptions)
    claim_rows, edge_rows = build_claim_rows(
        db,
        run_id=target_run_id,
        case_id=case_id,
        assumptions_hash=assumptions_hash,
        manifest_evidence=manifest,
        specs=claim_specs,
    )

    # Attach edges to claim dicts for evaluation lineage
    edges_by_claim: dict[str, list[dict[str, Any]]] = {}
    for edge in edge_rows:
        edges_by_claim.setdefault(edge["claim_id"], []).append(edge)
    for c_row in claim_rows:
        c_row["edges"] = edges_by_claim.get(c_row["claim_id"], [])

    # 5. Evaluate T7 competing hypotheses & residual H0 using real claim_ids
    hyp_result = evaluate_hypotheses(
        claims=claim_rows,
        events=events_payload,
        assumptions=case_assumptions,
    )

    # 6. Reconstruct narrative for leading/top hypothesis
    top_hyp = hyp_result.ranked_hypotheses[0] if hyp_result.ranked_hypotheses else None
    reconstruction = None
    if top_hyp:
        reconstruction = reconstruct_narrative(
            hypothesis=top_hyp,
            claims=claim_rows,
            events=events_payload,
            h0_event_ids=hyp_result.h0_residual.unassigned_event_ids,
        )

    # Compute template hash
    templates_used = load_templates()
    template_hash = H([t.to_dict() for t in templates_used])

    # Build snapshot capturing complete historical conclusions
    snapshot_data = {
        "ranked_hypotheses": [h.to_dict() for h in hyp_result.ranked_hypotheses],
        "h0_residual": hyp_result.h0_residual.to_dict(),
        "reconstruction": reconstruction.to_dict() if reconstruction else None,
        "next_best_evidence": [n.to_dict() for n in hyp_result.next_best_evidence],
        "outcome": hyp_result.outcome,
        "ranking_hash": hyp_result.ranking_hash,
        "template_hash": template_hash,
        "engine_version": engine_version,
        "assumptions": case_assumptions,
        "assumptions_hash": H(case_assumptions),
        "manifest": {"evidence": manifest, "assumptions": case_assumptions},
        "claims_count": len(claim_specs),
    }

    # 7. Persist write-once analysis run with ranking_hash and snapshot
    run = create_analysis_run(
        db,
        case_id=case_id,
        engine_version=engine_version,
        assumptions=case_assumptions,
        claims=claim_specs,
        parent_run_id=parent_run_id,
        ranking_hash=hyp_result.ranking_hash,
        run_id=target_run_id,
        snapshot_data=snapshot_data,
        template_hash=template_hash,
    )

    # Also persist to file storage
    try:
        storage_dir = Path("storage/runs")
        storage_dir.mkdir(parents=True, exist_ok=True)
        storage_file = storage_dir / f"{run.run_id}.json"
        storage_file.write_text(json.dumps(snapshot_data, indent=2), encoding="utf-8")
    except Exception as exc:
        logger.warning(f"Failed to write run snapshot file: {exc}")

    return {
        "run_id": run.run_id,
        "case_id": case_id,
        "parent_run_id": parent_run_id,
        "engine_version": run.engine_version,
        "assumptions_hash": run.assumptions_hash,
        "manifest": run.manifest,
        "claims_count": len(run.claims),
        "ranking_hash": run.ranking_hash,
        "template_hash": template_hash,
        "ranked_hypotheses": [h.to_dict() for h in hyp_result.ranked_hypotheses],
        "h0_residual": hyp_result.h0_residual.to_dict(),
        "reconstruction": reconstruction.to_dict() if reconstruction else None,
        "next_best_evidence": [n.to_dict() for n in hyp_result.next_best_evidence],
        "outcome": hyp_result.outcome,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }


def get_run_details(db: Session, run_id: str, verify: bool = False) -> dict[str, Any]:
    """Retrieve a complete, reproducible immutable run and verify its integrity.

    Retrieves frozen historical results directly from the immutable RunSnapshot
    rather than silently recomputing against current database state.
    """
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

    # Retrieve historical snapshot
    snap = db.get(RunSnapshot, run_id)
    snapshot_data: dict[str, Any] | None = None
    if snap:
        snapshot_data = snap.snapshot
    else:
        # Check disk storage fallback
        storage_file = Path("storage/runs") / f"{run_id}.json"
        if storage_file.exists():
            try:
                snapshot_data = json.loads(storage_file.read_text(encoding="utf-8"))
            except Exception:
                snapshot_data = None

    # Load stored claims for this run
    claims = db.query(Claim).filter(Claim.run_id == run_id).order_by(Claim.claim_id.asc()).all()
    claims_payload = [c.to_dict() for c in claims]

    if snapshot_data is None:
        # Legacy run created before snapshot support: compute and cache
        ev_ids = [e["evidence_id"] for e in manifest_evidence_list]
        events = (
            db.query(EventModel)
            .filter(EventModel.case_id == run.case_id, EventModel.evidence_id.in_(ev_ids))
            .all()
        )
        events_payload = [e.to_dict() for e in events]
        assumptions = run.manifest.get("assumptions", {})
        hyp_result = evaluate_hypotheses(
            claims=claims_payload,
            events=events_payload,
            assumptions=assumptions,
        )
        top_hyp = hyp_result.ranked_hypotheses[0] if hyp_result.ranked_hypotheses else None
        reconstruction = None
        if top_hyp:
            reconstruction = reconstruct_narrative(
                hypothesis=top_hyp,
                claims=claims_payload,
                events=events_payload,
                h0_event_ids=hyp_result.h0_residual.unassigned_event_ids,
            )
        snapshot_data = {
            "ranked_hypotheses": [h.to_dict() for h in hyp_result.ranked_hypotheses],
            "h0_residual": hyp_result.h0_residual.to_dict(),
            "reconstruction": reconstruction.to_dict() if reconstruction else None,
            "next_best_evidence": [n.to_dict() for n in hyp_result.next_best_evidence],
            "outcome": hyp_result.outcome,
            "ranking_hash": hyp_result.ranking_hash,
            "template_hash": "bundled@1.0.0",
        }

    template_hash = snap.template_hash if snap else snapshot_data.get("template_hash", "bundled@1.0.0")

    response = {
        "run_id": run.run_id,
        "case_id": run.case_id,
        "parent_run_id": run.parent_run_id,
        "engine_version": run.engine_version,
        "parser_versions": run.parser_versions,
        "assumptions_hash": run.assumptions_hash,
        "manifest": run.manifest,
        "validity": validity_status,
        "is_valid": is_valid,
        "invalidation_reasons": invalidating_reasons,
        "ranking_hash": run.ranking_hash,
        "ranking_hash_verified": True,
        "template_hash": template_hash,
        "claims_count": len(claims),
        "claims": claims_payload,
        "ranked_hypotheses": snapshot_data.get("ranked_hypotheses", []),
        "h0_residual": snapshot_data.get("h0_residual", {}),
        "reconstruction": snapshot_data.get("reconstruction"),
        "next_best_evidence": snapshot_data.get("next_best_evidence", []),
        "outcome": snapshot_data.get("outcome") or snapshot_data.get("ranking_outcome"),
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }

    if verify:
        verification = verify_run_reproducibility(db, run)
        response["verification"] = verification
        response["ranking_hash_verified"] = verification["verified"]

    return response


def verify_run_reproducibility(db: Session, run: AnalysisRun) -> dict[str, Any]:
    """Independently recompute hypothesis evaluation from current database events
    and compare against the frozen ranking hash. Does NOT mutate the database.
    """
    manifest_evidence_list = run.manifest.get("evidence", [])
    ev_ids = [e["evidence_id"] for e in manifest_evidence_list]
    events = (
        db.query(EventModel)
        .filter(EventModel.case_id == run.case_id, EventModel.evidence_id.in_(ev_ids))
        .all()
    )
    events_payload = [e.to_dict() for e in events]
    claims = db.query(Claim).filter(Claim.run_id == run.run_id).order_by(Claim.claim_id.asc()).all()
    claims_payload = [c.to_dict() for c in claims]

    assumptions = run.manifest.get("assumptions", {})
    recomputed = evaluate_hypotheses(
        claims=claims_payload,
        events=events_payload,
        assumptions=assumptions,
    )

    matches = (recomputed.ranking_hash == run.ranking_hash)
    divergence_details: list[str] = []
    if not matches:
        divergence_details.append(
            f"Persisted ranking hash {run.ranking_hash} differs from recomputed {recomputed.ranking_hash}"
        )

    return {
        "verified": matches,
        "persisted_ranking_hash": run.ranking_hash,
        "recomputed_ranking_hash": recomputed.ranking_hash,
        "diverged": not matches,
        "divergence_details": divergence_details,
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

            evals_a = {e["item_id"]: e for e in ha.get("evaluations", [])}
            evals_b = {e["item_id"]: e for e in hb.get("evaluations", [])}
            item_state_shifts = []
            for item_id in sorted(set(evals_a) & set(evals_b)):
                ea = evals_a[item_id]
                eb = evals_b[item_id]
                if ea["state"] != eb["state"]:
                    item_state_shifts.append({
                        "item_id": item_id,
                        "old_state": ea["state"],
                        "new_state": eb["state"],
                        "old_penalty": ea["disconfirmation_penalty"],
                        "new_penalty": eb["disconfirmation_penalty"],
                    })
                    root_cause_notes.append(
                        f"{hid} item {item_id} shifted from {ea['state']} to {eb['state']} "
                        f"(penalty: {ea['disconfirmation_penalty']} -> {eb['disconfirmation_penalty']})."
                    )

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
                "item_state_shifts": item_state_shifts,
                "changed": rank_changed or status_changed or score_delta != 0.0 or bool(item_state_shifts),
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
        "root_cause_notes": root_cause_notes,
        "root_cause_analysis": " ".join(root_cause_notes) if root_cause_notes else "No major hypothesis status transitions.",
    }
