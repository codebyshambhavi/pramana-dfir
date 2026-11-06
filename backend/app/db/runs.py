"""Role 3 / T3: write-once analysis runs (PRAMANA H″).

`create_analysis_run` is the only supported way to write a run. In one
transaction it inserts, in this order:

    claim_edge rows -> claim rows -> analysis_run row (last)

The children's foreign keys to the run are DEFERRABLE INITIALLY DEFERRED, so the
order is legal and a missing run row fails the commit. Once the run row exists,
database triggers reject any further child rows for it and any UPDATE or DELETE
of run data (app.db.db_guards). T7 will add its HypothesisEval / SourceCoverage
rows here, before the run row, once their schema is agreed.

The manifest freezes the inputs:
    {"evidence": [{"evidence_id", "sha256"}, ...],   # ACTIVE evidence only, sorted
     "assumptions": {...}}                             # as supplied by the caller
assumptions_hash = H(assumptions).

parser_versions is derived from the events stored for the manifest evidence, never
supplied by the caller:
    {"known": ["browser_csv@1.1.0", ...],         # sorted distinct values
     "unknown_evidence_ids": ["EVID-001", ...]}   # evidence with events lacking a version
Events stored before T3 have no parser_version. They are reported under
"unknown_evidence_ids" rather than given an invented version.

Nothing here commits; the caller commits (or rolls back) the transaction.
"""
from __future__ import annotations

import re
import uuid
from typing import Any, Sequence

from sqlalchemy import insert
from sqlalchemy.orm import Session

from app.db.claims import H, ClaimSpec, build_claim_rows
from app.db.models import (
    EVIDENCE_ACTIVE,
    AnalysisRun,
    Case,
    Claim,
    ClaimEdge,
    EventModel,
    Evidence,
    RunSnapshot,
    utc_now,
)

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class RunValidationError(ValueError):
    """Run inputs are invalid (unknown case/parent, bad ranking hash, bad assumptions)."""


def new_run_id() -> str:
    return f"RUN-{uuid.uuid4().hex[:12].upper()}"


def compute_assumptions_hash(assumptions: dict[str, Any]) -> str:
    return H(assumptions)


def manifest_evidence(db: Session, case_id: str) -> list[dict[str, str]]:
    """ACTIVE evidence of the case with intake SHA-256, sorted by evidence_id."""
    rows = (
        db.query(Evidence.evidence_id, Evidence.sha256)
        .filter(Evidence.case_id == case_id, Evidence.status == EVIDENCE_ACTIVE)
        .order_by(Evidence.evidence_id.asc())
        .all()
    )
    return [{"evidence_id": evidence_id, "sha256": sha256} for evidence_id, sha256 in rows]


def derive_parser_versions(db: Session, evidence_ids: Sequence[str]) -> dict[str, list[str]]:
    """Parser versions actually recorded on the stored events of these evidence items."""
    if not evidence_ids:
        return {"known": [], "unknown_evidence_ids": []}
    rows = (
        db.query(EventModel.evidence_id, EventModel.parser_version)
        .filter(EventModel.evidence_id.in_(list(evidence_ids)))
        .distinct()
        .all()
    )
    known = sorted({version for _, version in rows if version})
    unknown = sorted({evidence_id for evidence_id, version in rows if not version})
    return {"known": known, "unknown_evidence_ids": unknown}


def create_analysis_run(
    db: Session,
    case_id: str,
    *,
    engine_version: str,
    assumptions: dict[str, Any],
    claims: Sequence[ClaimSpec] = (),
    parent_run_id: str | None = None,
    ranking_hash: str | None = None,
    run_id: str | None = None,
    snapshot_data: dict[str, Any] | None = None,
    template_hash: str | None = None,
) -> AnalysisRun:
    """Write a complete run (claims and edges included) in the current transaction.

    Flushes pending ORM changes first, then inserts children and finally the run
    row. Does not commit. Raises RunValidationError / ClaimValidationError /
    LookupError before writing anything if inputs are invalid.
    """
    if db.get(Case, case_id) is None:
        raise LookupError(f"Case '{case_id}' not found")
    if not engine_version:
        raise RunValidationError("engine_version is required")
    if not isinstance(assumptions, dict):
        raise RunValidationError("assumptions must be a JSON object")
    if ranking_hash is not None and not _HEX64.match(ranking_hash):
        raise RunValidationError("ranking_hash must be a 64-character lowercase hex SHA-256")
    if parent_run_id is not None:
        parent = db.get(AnalysisRun, parent_run_id)
        if parent is None:
            raise RunValidationError(f"parent run {parent_run_id} not found")
        if parent.case_id != case_id:
            raise RunValidationError(f"parent run {parent_run_id} belongs to case {parent.case_id}")

    run_id = run_id or new_run_id()
    if db.get(AnalysisRun, run_id) is not None:
        raise RunValidationError(f"run {run_id} already exists")

    evidence = manifest_evidence(db, case_id)
    assumptions_hash = compute_assumptions_hash(assumptions)
    claim_rows, edge_rows = build_claim_rows(
        db,
        run_id=run_id,
        case_id=case_id,
        assumptions_hash=assumptions_hash,
        manifest_evidence=evidence,
        specs=claims,
    )
    run_row = {
        "run_id": run_id,
        "case_id": case_id,
        "parent_run_id": parent_run_id,
        "manifest": {"evidence": evidence, "assumptions": assumptions},
        "assumptions_hash": assumptions_hash,
        "engine_version": engine_version,
        "parser_versions": derive_parser_versions(db, [e["evidence_id"] for e in evidence]),
        "ranking_hash": ranking_hash,
        "created_at": utc_now(),
    }

    db.flush()  # nothing else pending may interleave with the ordered inserts below
    if edge_rows:
        db.execute(insert(ClaimEdge.__table__), edge_rows)
    if claim_rows:
        db.execute(insert(Claim.__table__), claim_rows)
    if snapshot_data is not None:
        snap_row = {
            "run_id": run_id,
            "case_id": case_id,
            "ranking_hash": ranking_hash,
            "template_hash": template_hash or "bundled@1.0.0",
            "snapshot": snapshot_data,
            "created_at": utc_now(),
        }
        db.execute(insert(RunSnapshot.__table__), [snap_row])
    db.execute(insert(AnalysisRun.__table__), [run_row])  # last: seals the run
    return db.get(AnalysisRun, run_id)
