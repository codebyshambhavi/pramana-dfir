"""Role 3 / T8: Immutable Analysis Runs & Run Diffing Service.

Provides deterministic write-once analysis run creation, verification,
reproducible retrieval, and semantic run diffing matching claims by claim_key.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

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
from intelligence.hyp.engine import evaluate_hypotheses
from intelligence.hyp.reconstruct import reconstruct_narrative
import intelligence.hyp.engine as hyp_engine


def load_templates():
    """Load current active hypothesis templates from intelligence package."""
    return hyp_engine.load_templates()

logger = logging.getLogger("pramana.services.runs")


def _normalize_timestamp(ts: Any) -> str | None:
    """Normalize timestamps consistently across ISO strings, datetimes, and timezones."""
    if ts is None:
        return None
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        else:
            ts = ts.astimezone(timezone.utc)
        return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if ts.microsecond else ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(ts, str):
        s = ts.strip()
        if not s:
            return ""
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt.microsecond else dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return s
    return str(ts)


def _canonicalize_json(val: Any) -> Any:
    """Recursively sort dict keys and normalize nested collections deterministically."""
    if val is None:
        return None
    if isinstance(val, dict):
        return {str(k): _canonicalize_json(v) for k, v in sorted(val.items())}
    if isinstance(val, (list, tuple)):
        return [_canonicalize_json(item) for item in val]
    if isinstance(val, str):
        stripped = val.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (stripped.startswith("[") and stripped.endswith("]")):
            try:
                parsed = json.loads(stripped)
                return _canonicalize_json(parsed)
            except Exception:
                pass
        return val
    return val


CANONICAL_EVENT_FIELDS: tuple[str, ...] = (
    "event_id",
    "case_id",
    "evidence_id",
    "artifact_ref",
    "sha256",
    "timestamp",
    "source",
    "family",
    "device",
    "actor",
    "action",
    "object",
    "ip",
    "location",
    "raw",
    "parser_version",
    "tz_assumption",
)


def canonical_event(event: Mapping[str, Any] | Any) -> dict[str, Any]:
    """Extract and canonicalize all 15+ event fields deterministically."""
    if hasattr(event, "to_dict"):
        event = event.to_dict()
    elif not isinstance(event, dict):
        event = dict(event)

    canon: dict[str, Any] = {}
    for f in CANONICAL_EVENT_FIELDS:
        if f not in event:
            canon[f] = None
            continue
        v = event[f]
        if v is None:
            canon[f] = None
        elif f == "timestamp":
            canon[f] = _normalize_timestamp(v)
        elif f in ("raw", "location"):
            canon[f] = _canonicalize_json(v)
        else:
            canon[f] = v
    return canon


def detect_event_drift(
    orig_events: Sequence[Mapping[str, Any] | Any],
    current_events: Sequence[Mapping[str, Any] | Any],
) -> tuple[bool, list[dict[str, Any]]]:
    """Detect field-level drift across all canonical event fields between
    preserved original events and current database events.
    Returns (events_identical, drift_details).
    """
    orig_canon_map: dict[str, dict[str, Any]] = {}
    for e in orig_events:
        c = canonical_event(e)
        eid = c.get("event_id")
        if eid:
            orig_canon_map[str(eid)] = c

    curr_canon_map: dict[str, dict[str, Any]] = {}
    for e in current_events:
        c = canonical_event(e)
        eid = c.get("event_id")
        if eid:
            curr_canon_map[str(eid)] = c

    drift_details: list[dict[str, Any]] = []

    # 1. Missing events (deleted from database)
    for eid in sorted(set(orig_canon_map.keys()) - set(curr_canon_map.keys())):
        drift_details.append({
            "event_id": eid,
            "type": "EVENT_REMOVED",
            "message": f"Event '{eid}' was present in original run snapshot but is missing from current database",
        })

    # 2. Added events (new events added to case)
    for eid in sorted(set(curr_canon_map.keys()) - set(orig_canon_map.keys())):
        drift_details.append({
            "event_id": eid,
            "type": "EVENT_ADDED",
            "message": f"Event '{eid}' is in current database but was not present in original run snapshot",
        })

    # 3. Field-level mutations for events present in both
    for eid in sorted(set(orig_canon_map.keys()) & set(curr_canon_map.keys())):
        orig_e = orig_canon_map[eid]
        curr_e = curr_canon_map[eid]
        for f in CANONICAL_EVENT_FIELDS:
            o_val = orig_e.get(f)
            c_val = curr_e.get(f)
            if o_val != c_val:
                drift_details.append({
                    "event_id": eid,
                    "type": "FIELD_MUTATED",
                    "field": f,
                    "original_value": o_val,
                    "current_value": c_val,
                    "message": f"Event '{eid}' field '{f}' drifted from {o_val!r} to {c_val!r}",
                })

    has_drift = len(drift_details) > 0
    return (not has_drift, drift_details)


def _normalize_time_window(tw: dict[str, Any] | None) -> dict[str, str | None] | None:
    """Normalize stage time window boundary timestamps for robust replay comparison."""
    if not tw or not isinstance(tw, dict):
        return None
    return {
        "lo": _normalize_timestamp(tw.get("lo")),
        "hi": _normalize_timestamp(tw.get("hi")),
    }


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

    case_tz = None
    if case_assumptions.get("case_timezone"):
        tz_name = str(case_assumptions["case_timezone"]).strip()
        if tz_name.upper() == "UTC":
            case_tz = timezone.utc
        else:
            try:
                from zoneinfo import ZoneInfo
                case_tz = ZoneInfo(tz_name)
            except Exception:
                case_tz = None

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
    claim_specs = generate_claims(events_payload, case_timezone=case_tz)

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

    # Load and preserve active templates
    templates_used = load_templates()
    template_dicts = [t.to_dict() for t in templates_used]
    template_hash = H(template_dicts)

    # 5. Evaluate T7 competing hypotheses & residual H0 using real claim_ids and preserved templates
    hyp_result = evaluate_hypotheses(
        claims=claim_rows,
        events=events_payload,
        assumptions=case_assumptions,
        templates=templates_used,
    )

    # 6. Reconstruct narrative for leading/top hypothesis using preserved templates
    top_hyp = hyp_result.ranked_hypotheses[0] if hyp_result.ranked_hypotheses else None
    reconstruction = None
    if top_hyp:
        reconstruction = reconstruct_narrative(
            hypothesis=top_hyp,
            claims=claim_rows,
            events=events_payload,
            h0_event_ids=hyp_result.h0_residual.unassigned_event_ids,
            templates=templates_used,
        )

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

    # Ranking hash verification requires an actual historical replay execution against preserved inputs.
    # Snapshot existence/authority != ranking hash verified.
    ranking_hash_verified = False
    if snapshot_data and snapshot_data.get("events") is not None and snapshot_data.get("templates") is not None:
        try:
            from intelligence.hyp.engine import HypothesisTemplate
            pres_events = snapshot_data["events"]
            pres_templates = [HypothesisTemplate.from_dict(t) for t in snapshot_data["templates"]]
            replay_res = evaluate_hypotheses(
                claims=claims_payload,
                events=pres_events,
                assumptions=run.manifest.get("assumptions", {}),
                templates=pres_templates,
            )
            snap_ranked = snapshot_data.get("ranked_hypotheses", [])
            snap_ranking_summary = [
                {"id": h.get("id"), "status": h.get("status"), "score": h.get("inconsistency_score"), "rank": h.get("rank")}
                for h in snap_ranked
            ]
            snap_ranking_hash = hashlib.sha256(
                json.dumps(snap_ranking_summary, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest() if snap_ranked else None
            snap_hash_field = snapshot_data.get("ranking_hash")

            ranking_hash_verified = (
                replay_res.ranking_hash == run.ranking_hash
                and (snap_ranking_hash == run.ranking_hash if snap_ranking_hash else True)
                and (snap_hash_field == run.ranking_hash if snap_hash_field else True)
            )
        except Exception as exc:
            logger.warning(f"Failed to verify ranking hash via replay for run '{run_id}': {exc}")
            ranking_hash_verified = False

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
        "ranking_hash_verified": ranking_hash_verified,
        "template_hash": template_hash,
        "snapshot_available": (snapshot_data is not None),
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
        response["historical_replay"] = verification["historical_replay"]
        response["current_state_comparison"] = verification["current_state_comparison"]
        response["ranking_hash_verified"] = (
            verification["historical_replay"]["verified"]
            and verification["historical_replay"]["ranking_hash_match"]
        )

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
    snapshot_status = "UNAVAILABLE"

    if snap:
        snapshot_data = snap.snapshot
        snapshot_source = "database"
        snapshot_authoritative = True
        snapshot_status = "AUTHORITATIVE_DB"
    else:
        storage_file = Path("storage/runs") / f"{run.run_id}.json"
        if storage_file.exists():
            try:
                snapshot_data = json.loads(storage_file.read_text(encoding="utf-8"))
                snapshot_source = "local_cache"
                snapshot_authoritative = False
                snapshot_status = "EPHEMERAL_LOCAL_FALLBACK"
            except Exception:
                snapshot_data = None
                snapshot_status = "UNAVAILABLE"

    snapshot_available = (snapshot_data is not None)

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
    preserved_events = snapshot_data.get("events") if snapshot_data else None
    preserved_templates_data = snapshot_data.get("templates") if snapshot_data else None

    # Replay requires both preserved events and preserved templates in the snapshot.
    # Never fall back to live events or disk templates during historical replay.
    replay_possible = bool(
        snapshot_data is not None
        and preserved_events is not None
        and preserved_templates_data is not None
    )

    replay_verified = False
    ranking_hash_match = False
    ranking_order_match = False
    h0_residual_match = False
    hypotheses_match = False
    reconstruction_match = False
    replay_discrepancies: list[str] = []

    if not replay_possible:
        missing_inputs = []
        if snapshot_data is None:
            missing_inputs.append("snapshot record missing")
        else:
            if preserved_events is None:
                missing_inputs.append("preserved input events missing from snapshot")
            if preserved_templates_data is None:
                missing_inputs.append("preserved templates missing from snapshot")
        discrepancy_msg = f"Historical replay unavailable: {', '.join(missing_inputs)}"
        replay_discrepancies.append(discrepancy_msg)
        historical_replay = {
            "status": "UNAVAILABLE",
            "verified": False,
            "replay_possible": False,
            "ranking_hash_match": False,
            "ranking_order_match": False,
            "h0_residual_match": False,
            "hypotheses_match": False,
            "reconstruction_match": False,
            "snapshot_source": snapshot_source,
            "snapshot_authoritative": snapshot_authoritative,
            "discrepancies": replay_discrepancies,
        }
    else:
        # Replay evaluation using preserved inputs only
        templates = [HypothesisTemplate.from_dict(t) for t in preserved_templates_data]
        assumptions = run.manifest.get("assumptions", {})

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
                f"Replay ranking hash '{replay_result.ranking_hash}' does not match persisted '{run.ranking_hash}'"
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
        expected_h0 = snapshot_data.get("h0_residual") or {}
        expected_h0_ids = sorted(expected_h0.get("unassigned_event_ids", []))
        replay_h0_ids = sorted(replay_result.h0_residual.unassigned_event_ids)
        expected_h0_count = expected_h0.get("unassigned_event_count", len(expected_h0_ids))
        replay_h0_count = replay_result.h0_residual.unassigned_event_count

        h0_match = True
        if replay_h0_ids != expected_h0_ids:
            h0_match = False
            replay_discrepancies.append(
                f"Replay H0 unassigned events ({len(replay_h0_ids)}) differ from snapshot ({len(expected_h0_ids)})"
            )
        if replay_h0_count != expected_h0_count:
            h0_match = False
            replay_discrepancies.append(
                f"Replay H0 unassigned count ({replay_h0_count}) differs from snapshot ({expected_h0_count})"
            )
        h0_residual_match = h0_match

        # 4. Hypotheses Evaluation Match
        expected_hyps = {h["id"]: h for h in snapshot_data.get("ranked_hypotheses", [])}
        hyp_match_all = True
        if len(replay_result.ranked_hypotheses) != len(expected_hyps):
            hyp_match_all = False
            replay_discrepancies.append(
                f"Replay evaluated {len(replay_result.ranked_hypotheses)} hypotheses; snapshot has {len(expected_hyps)}"
            )
        for h in replay_result.ranked_hypotheses:
            if h.id not in expected_hyps:
                hyp_match_all = False
                replay_discrepancies.append(f"Hypothesis '{h.id}' in replay was not in snapshot")
                continue
            exp = expected_hyps[h.id]
            if abs(h.inconsistency_score - exp.get("inconsistency_score", 0.0)) > 1e-4:
                hyp_match_all = False
                replay_discrepancies.append(
                    f"Hypothesis '{h.id}' inconsistency score {h.inconsistency_score} != snapshot {exp.get('inconsistency_score')}"
                )
            if h.status != exp.get("status"):
                hyp_match_all = False
                replay_discrepancies.append(
                    f"Hypothesis '{h.id}' status '{h.status}' != snapshot '{exp.get('status')}'"
                )
            if h.rank != exp.get("rank"):
                hyp_match_all = False
                replay_discrepancies.append(
                    f"Hypothesis '{h.id}' rank {h.rank} != snapshot {exp.get('rank')}"
                )

            # Compare individual item evaluations
            exp_evals = {e["item_id"]: e for e in exp.get("evaluations", []) if "item_id" in e}
            replay_evals = {e.item_id: e.to_dict() for e in h.evaluations}
            if len(exp_evals) != len(replay_evals):
                hyp_match_all = False
                replay_discrepancies.append(
                    f"Hypothesis '{h.id}' item evaluations count ({len(replay_evals)}) != snapshot ({len(exp_evals)})"
                )
            for item_id, r_eval in replay_evals.items():
                if item_id not in exp_evals:
                    hyp_match_all = False
                    replay_discrepancies.append(
                        f"Hypothesis '{h.id}' evaluation item '{item_id}' missing in snapshot"
                    )
                    continue
                x_eval = exp_evals[item_id]
                if r_eval.get("state") != x_eval.get("state"):
                    hyp_match_all = False
                    replay_discrepancies.append(
                        f"Hypothesis '{h.id}' item '{item_id}' state '{r_eval.get('state')}' != snapshot '{x_eval.get('state')}'"
                    )
                if r_eval.get("category") != x_eval.get("category"):
                    hyp_match_all = False
                    replay_discrepancies.append(
                        f"Hypothesis '{h.id}' item '{item_id}' category '{r_eval.get('category')}' != snapshot '{x_eval.get('category')}'"
                    )
                if abs(r_eval.get("disconfirmation_penalty", 0.0) - x_eval.get("disconfirmation_penalty", 0.0)) > 1e-4:
                    hyp_match_all = False
                    replay_discrepancies.append(
                        f"Hypothesis '{h.id}' item '{item_id}' penalty {r_eval.get('disconfirmation_penalty')} != snapshot {x_eval.get('disconfirmation_penalty')}"
                    )
                if sorted(r_eval.get("matched_claim_ids", [])) != sorted(x_eval.get("matched_claim_ids", [])):
                    hyp_match_all = False
                    replay_discrepancies.append(
                        f"Hypothesis '{h.id}' item '{item_id}' matched claims differ"
                    )
                if r_eval.get("witness_family") != x_eval.get("witness_family"):
                    hyp_match_all = False
                    replay_discrepancies.append(
                        f"Hypothesis '{h.id}' item '{item_id}' witness family '{r_eval.get('witness_family')}' != snapshot '{x_eval.get('witness_family')}'"
                    )
        hypotheses_match = hyp_match_all

        # 5. Narrative Reconstruction Match (using preserved templates)
        top_hyp = replay_result.ranked_hypotheses[0] if replay_result.ranked_hypotheses else None
        replay_reconstruction = None
        if top_hyp:
            replay_reconstruction = reconstruct_narrative(
                hypothesis=top_hyp,
                claims=claims_payload,
                events=preserved_events,
                h0_event_ids=replay_result.h0_residual.unassigned_event_ids,
                templates=templates,
            )
        expected_recon = snapshot_data.get("reconstruction")
        if expected_recon is None and replay_reconstruction is None:
            reconstruction_match = True
        elif expected_recon is None or replay_reconstruction is None:
            reconstruction_match = False
            replay_discrepancies.append("Reconstruction presence mismatch between replay and snapshot")
        else:
            recon_dict = replay_reconstruction.to_dict()
            recon_all_match = True
            if recon_dict.get("hypothesis_id") != expected_recon.get("hypothesis_id"):
                recon_all_match = False
                replay_discrepancies.append(
                    f"Reconstruction hypothesis_id '{recon_dict.get('hypothesis_id')}' != snapshot '{expected_recon.get('hypothesis_id')}'"
                )
            if recon_dict.get("status") != expected_recon.get("status"):
                recon_all_match = False
                replay_discrepancies.append(
                    f"Reconstruction status '{recon_dict.get('status')}' != snapshot '{expected_recon.get('status')}'"
                )
            if recon_dict.get("narrative_summary") != expected_recon.get("narrative_summary"):
                recon_all_match = False
                replay_discrepancies.append("Reconstruction narrative_summary differs from snapshot")
            if recon_dict.get("background_activity_count") != expected_recon.get("background_activity_count"):
                recon_all_match = False
                replay_discrepancies.append(
                    f"Reconstruction background_activity_count ({recon_dict.get('background_activity_count')}) != snapshot ({expected_recon.get('background_activity_count')})"
                )
            if sorted(recon_dict.get("background_activity_event_ids", [])) != sorted(expected_recon.get("background_activity_event_ids", [])):
                recon_all_match = False
                replay_discrepancies.append("Reconstruction background_activity_event_ids differ from snapshot")
            if recon_dict.get("residual_h0_count") != expected_recon.get("residual_h0_count"):
                recon_all_match = False
                replay_discrepancies.append(
                    f"Reconstruction residual_h0_count ({recon_dict.get('residual_h0_count')}) != snapshot ({expected_recon.get('residual_h0_count')})"
                )
            if sorted(recon_dict.get("residual_h0_event_ids", [])) != sorted(expected_recon.get("residual_h0_event_ids", [])):
                recon_all_match = False
                replay_discrepancies.append("Reconstruction residual_h0_event_ids differ from snapshot")

            # Compare stages in order
            exp_stages = expected_recon.get("stages", [])
            rep_stages = recon_dict.get("stages", [])
            if len(exp_stages) != len(rep_stages):
                recon_all_match = False
                replay_discrepancies.append(
                    f"Reconstruction stages count ({len(rep_stages)}) != snapshot ({len(exp_stages)})"
                )
            else:
                for idx, (exp_s, rep_s) in enumerate(zip(exp_stages, rep_stages)):
                    s_name = exp_s.get("stage_name", f"stage_{idx}")
                    if rep_s.get("stage_name") != exp_s.get("stage_name"):
                        recon_all_match = False
                        replay_discrepancies.append(
                            f"Stage {idx} name '{rep_s.get('stage_name')}' != snapshot '{exp_s.get('stage_name')}'"
                        )
                    if rep_s.get("status") != exp_s.get("status"):
                        recon_all_match = False
                        replay_discrepancies.append(
                            f"Stage '{s_name}' status '{rep_s.get('status')}' != snapshot '{exp_s.get('status')}'"
                        )
                    if _normalize_time_window(rep_s.get("time_window")) != _normalize_time_window(exp_s.get("time_window")):
                        recon_all_match = False
                        replay_discrepancies.append(
                            f"Stage '{s_name}' time window {rep_s.get('time_window')} != snapshot {exp_s.get('time_window')}"
                        )
                    if rep_s.get("relationship_to_previous") != exp_s.get("relationship_to_previous"):
                        recon_all_match = False
                        replay_discrepancies.append(
                            f"Stage '{s_name}' relationship '{rep_s.get('relationship_to_previous')}' != snapshot '{exp_s.get('relationship_to_previous')}'"
                        )
                    rep_evs = sorted([e.get("event_id") for e in rep_s.get("raw_events", []) if isinstance(e, dict) and "event_id" in e])
                    exp_evs = sorted([e.get("event_id") for e in exp_s.get("raw_events", []) if isinstance(e, dict) and "event_id" in e])
                    if rep_evs != exp_evs:
                        recon_all_match = False
                        replay_discrepancies.append(
                            f"Stage '{s_name}' raw_events differ from snapshot"
                        )
                    rep_cls = sorted([c.get("claim_id") for c in rep_s.get("claims", []) if isinstance(c, dict) and "claim_id" in c])
                    exp_cls = sorted([c.get("claim_id") for c in exp_s.get("claims", []) if isinstance(c, dict) and "claim_id" in c])
                    if rep_cls != exp_cls:
                        recon_all_match = False
                        replay_discrepancies.append(
                            f"Stage '{s_name}' claims differ from snapshot"
                        )
            reconstruction_match = recon_all_match

        replay_verified = (
            ranking_hash_match
            and ranking_order_match
            and h0_residual_match
            and hypotheses_match
            and reconstruction_match
        )

        historical_replay = {
            "status": "VERIFIED" if replay_verified else "FAILED",
            "verified": replay_verified,
            "replay_possible": True,
            "ranking_hash_match": ranking_hash_match,
            "ranking_order_match": ranking_order_match,
            "h0_residual_match": h0_residual_match,
            "hypotheses_match": hypotheses_match,
            "reconstruction_match": reconstruction_match,
            "snapshot_source": snapshot_source,
            "snapshot_authoritative": snapshot_authoritative,
            "discrepancies": replay_discrepancies,
        }

    # --- Operation 2: Current State Comparison ---
    manifest_evidence_list = run.manifest.get("evidence", [])
    ev_ids = [e["evidence_id"] for e in manifest_evidence_list]
    current_db_events = (
        db.query(EventModel)
        .filter(EventModel.case_id == run.case_id, EventModel.evidence_id.in_(ev_ids))
        .all()
    )
    current_events_payload = [e.to_dict() for e in current_db_events]

    # Detect field-level drift across all canonical event fields
    orig_events = snapshot_data.get("events", []) if snapshot_data else []
    events_identical, drift_details = detect_event_drift(orig_events, current_events_payload)

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

    matches_current_state = (
        (current_recomputed.ranking_hash == run.ranking_hash)
        and events_identical
        and templates_identical
    )
    divergence_reasons: list[str] = []
    if current_recomputed.ranking_hash != run.ranking_hash:
        divergence_reasons.append(
            f"Persisted ranking hash {run.ranking_hash} differs from current database recomputation {current_recomputed.ranking_hash}"
        )
    if not events_identical:
        divergence_reasons.append(
            f"Underlying case events in database have drifted: {len(drift_details)} change(s) detected"
        )
        for d in drift_details:
            divergence_reasons.append(d["message"])
    if not templates_identical:
        divergence_reasons.append("Active hypothesis templates on disk differ from templates used at run creation")

    overall_verified = matches_current_state and replay_verified
    overall_diverged = not matches_current_state

    return {
        "verified": overall_verified,
        "persisted_ranking_hash": run.ranking_hash,
        "recomputed_ranking_hash": current_recomputed.ranking_hash,
        "diverged": overall_diverged,
        "divergence_details": divergence_reasons,
        "snapshot_available": snapshot_available,
        "snapshot_authoritative": snapshot_authoritative,
        "snapshot_status": snapshot_status,
        "ranking_hash_verified": replay_verified and ranking_hash_match,
        "historical_replay": historical_replay,
        "current_state_comparison": {
            "diverged": overall_diverged,
            "events_identical": events_identical,
            "templates_identical": templates_identical,
            "current_ranking_hash": current_recomputed.ranking_hash,
            "divergence_reasons": divergence_reasons,
            "event_drift_detected": not events_identical,
            "event_drift_details": drift_details,
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
