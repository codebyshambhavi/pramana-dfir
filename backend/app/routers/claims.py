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
    summary="Create an immutable analysis run with T5 correlation and T6 claims",
)
def create_case_run(
    case_id: str,
    payload: RunCreateRequest | None = None,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Execute T5 correlation and T6 claim generation, persisting an immutable run."""
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{case_id}' not found",
        )

    req = payload or RunCreateRequest()

    # Load active evidence manifest
    manifest = manifest_evidence(db, case_id)
    if not manifest:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Case '{case_id}' has no ACTIVE evidence to analyze",
        )

    # Load stored case events
    events = db.query(EventModel).filter(EventModel.case_id == case_id).all()
    events_payload = [e.to_dict() for e in events]

    # Generate T5 candidates and T6 claims
    claim_specs = generate_claims(events_payload)

    # Create immutable write-once analysis run
    run = create_analysis_run(
        db,
        case_id=case_id,
        engine_version=req.engine_version,
        assumptions=req.assumptions,
        claims=claim_specs,
        parent_run_id=req.parent_run_id,
    )
    db.commit()

    return {
        "run_id": run.run_id,
        "case_id": case_id,
        "claims_count": len(run.claims),
        "manifest": run.manifest,
        "assumptions_hash": run.assumptions_hash,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }


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
    summary="Retrieve an analysis run",
)
def get_case_run(case_id: str, run_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve metadata for a specific analysis run."""
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
    return run.to_dict()


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
