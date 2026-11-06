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

    # Compute template hash and preserve template definitions
    templates_used = load_templates()
    template_dicts = [t.to_dict() for t in templates_used]
    template_hash = H(template_dicts)

    # Build snapshot capturing complete historical conclusions and original inputs
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
        "events": events_payload,
        "templates": template_dicts,
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

    # Retrieve historical snapshot: database is authoritative
    snap = db.get(RunSnapshot, run_id)
    snapshot_data: dict[str, Any] | None = None
    snapshot_source: str | None = None
    snapshot_authoritative: bool = False
    snapshot_status: str = "UNAVAILABLE"
    snapshot_warning: str | None = None

    if snap:
        snapshot_data = snap.snapshot
        snapshot_source = "database"
        snapshot_authoritative = True
        snapshot_status = "AUTHORITATIVE_DB"
    else:
        # Check disk storage fallback (ephemeral local cache only; not durable production storage)
        storage_file = Path("storage/runs") / f"{run_id}.json"
        if storage_file.exists():
            try:
                snapshot_data = json.loads(storage_file.read_text(encoding="utf-8"))
                snapshot_source = "local_cache"
                snapshot_authoritative = False
                snapshot_status = "EPHEMERAL_LOCAL_FALLBACK"
                snapshot_warning = "Local filesystem fallback is ephemeral and non-authoritative for production audit"
            except Exception:
                snapshot_data = None
                snapshot_status = "UNAVAILABLE"
                snapshot_warning = "Local snapshot cache was corrupted and could not be loaded"
        else:
            snapshot_status = "UNAVAILABLE"
            snapshot_warning = "Analysis run snapshot is unavailable; historical conclusions cannot be verified"

    # Load stored claims and edges for this run
    claims = db.query(Claim).filter(Claim.run_id == run_id).order_by(Claim.claim_id.asc()).all()
    edges = db.query(ClaimEdge).filter(ClaimEdge.run_id == run_id).all()
    edges_by_claim: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        edges_by_claim.setdefault(edge.claim_id, []).append(edge.to_dict())
    claims_payload = []
    for c in claims:
        cd = c.to_dict()
        cd["edges"] = edges_by_claim.get(c.claim_id, [])
        claims_payload.append(cd)

    template_hash = snap.template_hash if snap else (
        snapshot_data.get("template_hash", "bundled@1.0.0") if snapshot_data else "bundled@1.0.0"
    )

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
        "ranking_hash_verified": True if snapshot_data is not None else False,
        "template_hash": template_hash,
        "snapshot_status": snapshot_status,
        "snapshot_source": snapshot_source,
        "snapshot_authoritative": snapshot_authoritative,
        "claims_count": len(claims),
        "claims": claims_payload,
        "ranked_hypotheses": snapshot_data.get("ranked_hypotheses", []) if snapshot_data else [],
        "h0_residual": snapshot_data.get("h0_residual") if snapshot_data else None,
        "reconstruction": snapshot_data.get("reconstruction") if snapshot_data else None,
        "next_best_evidence": snapshot_data.get("next_best_evidence", []) if snapshot_data else [],
        "outcome": (snapshot_data.get("outcome") or snapshot_data.get("ranking_outcome")) if snapshot_data else None,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }

    if snapshot_warning:
        response["snapshot_warning"] = snapshot_warning

    if verify:
        verification = verify_run_reproducibility(db, run)
        response["verification"] = verification
        response["ranking_hash_verified"] = verification["verified"]

    return response


def verify_run_reproducibility(db: Session, run: AnalysisRun) -> dict[str, Any]:
    """Independently verify an analysis run through two explicit operations:
    1. Historical Replay: Replays evaluation using the preserved original input events
       and preserved hypothesis templates stored in the immutable snapshot. Verifies
       ranking, H0 residual, hypotheses evaluation, and reconstruction narrative.
    2. Current State Comparison: Compares current live database events and current
       hypothesis templates on disk against the run, detecting any data drift or mutation.

    Does NOT mutate the database.
    """
    from intelligence.hyp.engine import HypothesisTemplate

    # 1. Retrieve snapshot
    snap = db.get(RunSnapshot, run.run_id)
    snapshot_data: dict[str, Any] | None = None
    snapshot_source: str | None = None
    snapshot_authoritative = False

    if snap:
        snapshot_data = snap.snapshot
        snapshot_source = "database"
        snapshot_authoritative = True
    else:
        storage_file = Path("storage/runs") / f"{run.run_id}.json"
        if storage_file.exists():
            try:
                snapshot_data = json.loads(storage_file.read_text(encoding="utf-8"))
                snapshot_source = "local_cache"
                snapshot_authoritative = False
            except Exception:
                snapshot_data = None

    # Load stored claims and edges for this run
    claims = db.query(Claim).filter(Claim.run_id == run.run_id).order_by(Claim.claim_id.asc()).all()
    edges = db.query(ClaimEdge).filter(ClaimEdge.run_id == run.run_id).all()
    edges_by_claim: dict[str, list[dict[str, Any]]] = {}
    for edge in edges:
        edges_by_claim.setdefault(edge.claim_id, []).append(edge.to_dict())
    claims_payload = []
    for c in claims:
        cd = c.to_dict()
        cd["edges"] = edges_by_claim.get(c.claim_id, [])
        claims_payload.append(cd)

    # --- Operation 1: Historical Replay ---
    replay_possible = snapshot_data is not None
    replay_verified = False
    ranking_hash_match = False
    ranking_order_match = False
    h0_residual_match = False
    hypotheses_match = False
    reconstruction_match = False
    replay_discrepancies: list[str] = []

    if replay_possible:
        # Extract preserved inputs
        preserved_events = snapshot_data.get("events")
        preserved_templates_data = snapshot_data.get("templates")

        if preserved_events is None:
            manifest_evidence_list = run.manifest.get("evidence", [])
            ev_ids = [e["evidence_id"] for e in manifest_evidence_list]
            ev_objs = (
                db.query(EventModel)
                .filter(EventModel.case_id == run.case_id, EventModel.evidence_id.in_(ev_ids))
                .all()
            )
            preserved_events = [e.to_dict() for e in ev_objs]

        if preserved_templates_data is not None:
            templates = [HypothesisTemplate.from_dict(t) for t in preserved_templates_data]
        else:
            templates = load_templates()

        assumptions = run.manifest.get("assumptions", {})

        # Replay evaluation from preserved inputs
        replay_result = evaluate_hypotheses(
            claims=claims_payload,
            events=preserved_events,
            assumptions=assumptions,
            templates=templates,
        )

        # 1. Ranking Hash Match
        ranking_hash_match = (replay_result.ranking_hash == run.ranking_hash)
        if not ranking_hash_match:
            replay_discrepancies.append(
                f"Replay ranking hash {replay_result.ranking_hash} does not match persisted {run.ranking_hash}"
            )

        # 2. Ranking Order & Scores Match
        expected_hyp_ids = [h["id"] for h in snapshot_data.get("ranked_hypotheses", [])]
        replay_hyp_ids = [h.id for h in replay_result.ranked_hypotheses]
        ranking_order_match = (replay_hyp_ids == expected_hyp_ids)
        if not ranking_order_match:
            replay_discrepancies.append(
                f"Replay ranking order {replay_hyp_ids} differs from snapshot {expected_hyp_ids}"
            )

        # 3. H0 Residual Match
        expected_h0_ids = sorted(snapshot_data.get("h0_residual", {}).get("unassigned_event_ids", []) if snapshot_data.get("h0_residual") else [])
        replay_h0_ids = sorted(replay_result.h0_residual.unassigned_event_ids)
        h0_residual_match = (replay_h0_ids == expected_h0_ids)
        if not h0_residual_match:
            replay_discrepancies.append(
                f"Replay H0 unassigned events ({len(replay_h0_ids)}) differ from snapshot ({len(expected_h0_ids)})"
            )

        # 4. Hypotheses Evaluation Match
        expected_hyps = {h["id"]: h for h in snapshot_data.get("ranked_hypotheses", [])}
        hyp_match_all = True
        for h in replay_result.ranked_hypotheses:
            if h.id in expected_hyps:
                exp = expected_hyps[h.id]
                if abs(h.inconsistency_score - exp.get("inconsistency_score", 0.0)) > 1e-4:
                    hyp_match_all = False
                    replay_discrepancies.append(
                        f"Hypothesis {h.id} inconsistency score {h.inconsistency_score} != snapshot {exp.get('inconsistency_score')}"
                    )
                if h.status != exp.get("status"):
                    hyp_match_all = False
                    replay_discrepancies.append(
                        f"Hypothesis {h.id} status '{h.status}' != snapshot '{exp.get('status')}'"
                    )
            else:
                hyp_match_all = False
        hypotheses_match = hyp_match_all

        # 5. Narrative Reconstruction Match
        top_hyp = replay_result.ranked_hypotheses[0] if replay_result.ranked_hypotheses else None
        replay_reconstruction = None
        if top_hyp:
            replay_reconstruction = reconstruct_narrative(
                hypothesis=top_hyp,
                claims=claims_payload,
                events=preserved_events,
                h0_event_ids=replay_result.h0_residual.unassigned_event_ids,
            )
        expected_recon = snapshot_data.get("reconstruction")
        if expected_recon is None and replay_reconstruction is None:
            reconstruction_match = True
        elif expected_recon is not None and replay_reconstruction is not None:
            recon_dict = replay_reconstruction.to_dict()
            exp_stages = {s.get("stage_name", s.get("stage")): s.get("status") for s in expected_recon.get("stages", [])}
            replay_stages = {s.get("stage_name", s.get("stage")): s.get("status") for s in recon_dict.get("stages", [])}
            reconstruction_match = (
                exp_stages == replay_stages
                and expected_recon.get("status") == recon_dict.get("status")
            )
            if not reconstruction_match:
                replay_discrepancies.append("Replay narrative reconstruction stages differ from snapshot")
        else:
            reconstruction_match = False
            replay_discrepancies.append("Reconstruction presence mismatch between replay and snapshot")

        replay_verified = (
            ranking_hash_match
            and ranking_order_match
            and h0_residual_match
            and hypotheses_match
            and reconstruction_match
        )

    # --- Operation 2: Current State Comparison ---
    manifest_evidence_list = run.manifest.get("evidence", [])
    ev_ids = [e["evidence_id"] for e in manifest_evidence_list]
    current_db_events = (
        db.query(EventModel)
        .filter(EventModel.case_id == run.case_id, EventModel.evidence_id.in_(ev_ids))
        .all()
    )
    current_events_payload = [e.to_dict() for e in current_db_events]

    events_identical = True
    if snapshot_data and "events" in snapshot_data:
        orig_events = snapshot_data["events"]
        if len(orig_events) != len(current_events_payload):
            events_identical = False
        else:
            orig_map = {e["event_id"]: e for e in orig_events if "event_id" in e}
            for ce in current_events_payload:
                eid = ce.get("event_id")
                if eid not in orig_map:
                    events_identical = False
                    break
                oe = orig_map[eid]
                for f in ("action", "actor", "device", "timestamp", "object", "ip"):
                    if ce.get(f) != oe.get(f):
                        events_identical = False
                        break

    current_disk_templates = load_templates()
    current_template_hash = H([t.to_dict() for t in current_disk_templates])
    snap_template_hash = snap.template_hash if snap else (snapshot_data.get("template_hash") if snapshot_data else None)
    templates_identical = (current_template_hash == snap_template_hash) if snap_template_hash else True

    current_recomputed = evaluate_hypotheses(
        claims=claims_payload,
        events=current_events_payload,
        assumptions=run.manifest.get("assumptions", {}),
        templates=current_disk_templates,
    )

    matches_current_state = (current_recomputed.ranking_hash == run.ranking_hash)
    divergence_reasons: list[str] = []
    if not matches_current_state:
        divergence_reasons.append(
            f"Persisted ranking hash {run.ranking_hash} differs from current database recomputation {current_recomputed.ranking_hash}"
        )
        if not events_identical:
            divergence_reasons.append("Underlying case events in database have been modified or removed since run was sealed")
        if not templates_identical:
            divergence_reasons.append("Active hypothesis templates on disk differ from templates used at run creation")

    return {
        "verified": matches_current_state,
        "persisted_ranking_hash": run.ranking_hash,
        "recomputed_ranking_hash": current_recomputed.ranking_hash,
        "diverged": not matches_current_state,
        "divergence_details": divergence_reasons,
        "historical_replay": {
            "status": "VERIFIED" if replay_verified else ("FAILED" if replay_possible else "UNAVAILABLE"),
            "verified": replay_verified,
            "replay_possible": replay_possible,
            "ranking_hash_match": ranking_hash_match,
            "ranking_order_match": ranking_order_match,
            "h0_residual_match": h0_residual_match,
            "hypotheses_match": hypotheses_match,
            "reconstruction_match": reconstruction_match,
            "snapshot_source": snapshot_source,
            "snapshot_authoritative": snapshot_authoritative,
            "discrepancies": replay_discrepancies,
        },
        "current_state_comparison": {
            "diverged": not matches_current_state,
            "events_identical": events_identical,
            "templates_identical": templates_identical,
            "current_ranking_hash": current_recomputed.ranking_hash,
            "divergence_reasons": divergence_reasons,
        },
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
