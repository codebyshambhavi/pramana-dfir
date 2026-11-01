"""Role 3 / T3: analysis run foundation.

A run freezes its inputs when it is created. The evidence snapshot records every
evidence item of the case with its intake SHA-256 and status at that moment, and
whether it is an input (`included`). Only ACTIVE and VERIFIED evidence is
included; QUARANTINED and REMOVED evidence is listed but excluded, so the run
records what it did not use and why.

Filling a run with claims, edges, evaluations and coverage is the analysis
layer's job. This module only creates and finalizes runs. Immutability of
finalized runs is enforced in app.db.models at flush time.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.db.models import (
    EVIDENCE_ACTIVE,
    EVIDENCE_VERIFIED,
    RUN_COMPLETED,
    RUN_FAILED,
    RUN_RUNNING,
    AnalysisRun,
    Case,
    Evidence,
    utc_now,
)

INCLUDED_EVIDENCE_STATUSES = (EVIDENCE_ACTIVE, EVIDENCE_VERIFIED)


def snapshot_digest(snapshot: list[dict[str, Any]]) -> str:
    """SHA-256 of the snapshot in canonical JSON (sorted keys, no whitespace)."""
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_evidence_snapshot(db: Session, case_id: str) -> list[dict[str, Any]]:
    items = (
        db.query(Evidence)
        .filter(Evidence.case_id == case_id)
        .order_by(Evidence.evidence_id.asc())
        .all()
    )
    snapshot = []
    for ev in items:
        status = ev.status or EVIDENCE_ACTIVE
        snapshot.append({
            "evidence_id": ev.evidence_id,
            "sha256": ev.sha256,
            "status": status,
            "included": status in INCLUDED_EVIDENCE_STATUSES,
        })
    return snapshot


def create_analysis_run(
    db: Session,
    case_id: str,
    *,
    engine_version: str | None = None,
    config: dict[str, Any] | None = None,
) -> AnalysisRun:
    """Create a RUNNING run for a case with a frozen evidence snapshot. Flushes, does not commit."""
    if db.get(Case, case_id) is None:
        raise LookupError(f"Case '{case_id}' not found")
    snapshot = build_evidence_snapshot(db, case_id)
    run = AnalysisRun(
        run_id=f"RUN-{uuid.uuid4().hex[:12].upper()}",
        case_id=case_id,
        status=RUN_RUNNING,
        engine_version=engine_version,
        config=config,
        evidence_snapshot=snapshot,
        input_digest=snapshot_digest(snapshot),
    )
    db.add(run)
    db.flush()
    return run


def finalize_run(db: Session, run: AnalysisRun, *, error: str | None = None) -> AnalysisRun:
    """Mark a RUNNING run COMPLETED (or FAILED when `error` is given). Flushes, does not commit.

    After this flush the run and its child rows can no longer change.
    """
    if run.status != RUN_RUNNING:
        raise ValueError(f"Run {run.run_id} is {run.status}; only RUNNING runs can be finalized")
    run.status = RUN_FAILED if error else RUN_COMPLETED
    run.error = error
    run.completed_at = utc_now()
    db.flush()
    return run
