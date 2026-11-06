"""Role 3 / T5+T6: Claims, Lineage, Runs, and Correlation router.

Endpoints:
- POST /cases/{case_id}/runs: Create an immutable analysis run executing T5+T6
- GET /cases/{case_id}/runs: List all immutable runs for a case
- GET /cases/{case_id}/runs/{run_id}: Get metadata of one run
- GET /cases/{case_id}/runs/{run_id}/claims: List all claims in a run
- GET /runs/{run_id}/claims/{claim_id}: Retrieve one specific claim
- GET /runs/{run_id}/claims/{claim_id}/lineage: Full lineage from claim to evidence SHA-256
- GET /cases/{case_id}/runs/{run_id}/correlations: Inspect T5 candidate and promoted relationships
"""
from __future__ import annotations

import os
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.claims import claim_lineage
from app.db.models import AnalysisRun, Case, Claim, EventModel, Evidence
from app.db.runs import create_analysis_run, manifest_evidence
from app.db.session import get_db
from app.services.runs import (
    diff_runs,
    execute_analysis_run,
    get_run_details,
    verify_run_reproducibility,
)
from intelligence.claims import generate_claims
from intelligence.correlate import correlate_events

router = APIRouter(tags=["claims"])


class RunCreateRequest(BaseModel):
    engine_version: str = Field("pramana-engine@1.0.0", examples=["pramana-engine@1.0.0"])
    assumptions: dict[str, Any] = Field(default_factory=lambda: {"case_timezone": "UTC"})
    parent_run_id: str | None = Field(None, examples=["RUN-001"])


@router.post(
    "/cases/{case_id}/runs",
    status_code=status.HTTP_201_CREATED,
    summary="Create an immutable analysis run with T5-T8 correlation, claims, and hypothesis evaluation",
)
def create_case_run(
    case_id: str,
    payload: RunCreateRequest | None = None,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Execute T5 correlation, T6 claim generation, and T7 hypothesis evaluation, persisting an immutable run."""
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    req = payload or RunCreateRequest()

    try:
        run_data = execute_analysis_run(
            db,
            case_id=case_id,
            engine_version=req.engine_version,
            assumptions=req.assumptions,
            parent_run_id=req.parent_run_id,
        )
        db.commit()
        return run_data
    except LookupError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise


@router.get(
    "/cases/{case_id}/runs",
    summary="List immutable analysis runs for a case",
)
def list_case_runs(case_id: str, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """List all analysis runs for a given case."""
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    runs = (
        db.query(AnalysisRun)
        .filter(AnalysisRun.case_id == case_id)
        .order_by(AnalysisRun.created_at.desc())
        .all()
    )
    return [r.to_dict() for r in runs]


@router.get(
    "/cases/{case_id}/runs/{run_id}",
    summary="Retrieve an analysis run with full reproducible details",
)
def get_case_run(case_id: str, run_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve metadata and evaluation for a specific analysis run."""
    try:
        details = get_run_details(db, run_id)
        if details["case_id"] != case_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Run '{run_id}' does not belong to case '{case_id}'",
            )
        return details
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.get(
    "/runs/{run_id}",
    summary="Retrieve complete, reproducible immutable run",
)
def get_run_endpoint(
    run_id: str,
    verify: bool = False,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Retrieve complete immutable run with inputs, claims, ranked hypotheses, H0, and reconstruction."""
    try:
        return get_run_details(db, run_id, verify=verify)
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.post(
    "/runs/{run_id}/verify",
    summary="Independently verify immutable run reproducibility",
)
def verify_run_endpoint(run_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Independently recomputes from historical inputs and confirms whether the result
    matches the persisted hash, without mutating the original run.
    """
    try:
        run = db.get(AnalysisRun, run_id)
        if not run:
            raise LookupError(f"AnalysisRun '{run_id}' not found")
        return verify_run_reproducibility(db, run)
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.get(
    "/runs/{run_a_id}/diff/{run_b_id}",
    summary="Compare two immutable runs matching claims by claim_key",
)
def diff_runs_endpoint(run_a_id: str, run_b_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Compare two immutable runs matching claims by claim_key, explaining ranking and conclusion changes."""
    try:
        return diff_runs(db, run_a_id, run_b_id)
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.get(
    "/cases/{case_id}/runs/{run_id}/claims",
    summary="List claims for a case run",
)
def list_run_claims(case_id: str, run_id: str, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """Retrieve all content-addressed claims for a given run."""
    run = db.query(AnalysisRun).filter(AnalysisRun.run_id == run_id).first()
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run '{run_id}' not found",
        )
    if run.case_id != case_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run '{run_id}' does not belong to case '{case_id}'",
        )

    claims = db.query(Claim).filter(Claim.run_id == run_id).order_by(Claim.claim_id.asc()).all()
    return [c.to_dict() for c in claims]


@router.get(
    "/runs/{run_id}/claims/{claim_id}",
    summary="Retrieve a single claim",
)
def get_single_claim(run_id: str, claim_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve one specific claim from a run."""
    claim = db.get(Claim, (run_id, claim_id))
    if not claim:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Claim '{claim_id}' not found in run '{run_id}'",
        )
    return claim.to_dict()


@router.get(
    "/runs/{run_id}/claims/{claim_id}/lineage",
    summary="Retrieve complete claim lineage",
)
def get_claim_lineage_endpoint(run_id: str, claim_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve complete evidence lineage for a claim down to the intake SHA-256."""
    try:
        lineage = claim_lineage(db, run_id, claim_id)
        return lineage
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc


@router.get(
    "/cases/{case_id}/runs/{run_id}/correlations",
    summary="Inspect candidate and promoted event relationships",
)
def get_run_correlations(case_id: str, run_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Inspect T5 candidate generation results and promoted relationships.

    Does NOT expose unpromoted links as established forensic facts.
    """
    run = db.query(AnalysisRun).filter(AnalysisRun.run_id == run_id).first()
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run '{run_id}' not found",
        )
    if run.case_id != case_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run '{run_id}' does not belong to case '{case_id}'",
        )

    events = db.query(EventModel).filter(EventModel.case_id == case_id).all()
    events_payload = [e.to_dict() for e in events]

    all_candidates, promoted = correlate_events(events_payload)

    return {
        "run_id": run_id,
        "case_id": case_id,
        "total_candidates_evaluated": len(all_candidates),
        "promoted_count": len(promoted),
        "promoted_relationships": [p.to_dict() for p in promoted],
        "candidates": [c.to_dict() for c in all_candidates],
    }
