"""Role 3: Findings, Lineage, and Analysis router.

Endpoints:
- POST /cases/{id}/analyze: Trigger analysis and store generated findings
- GET /cases/{id}/findings: List all findings for a case
- PATCH /findings/{id}: Investigator review approval/rejection
- GET /findings/{id}/lineage: Full provenance chain from finding to evidence and SHA-256
"""
from __future__ import annotations

import os
import uuid
from typing import Any, Literal
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.models import Case, EventModel, FindingModel, FindingReviewDecision
from app.db.runs import create_analysis_run, manifest_evidence
from app.db.session import get_db
from app.reports.lineage import get_finding_lineage
from app.services.pipeline import execute_analyze
from app.services.runs import execute_analysis_run
from intelligence.claims import generate_claims

router = APIRouter(tags=["findings"])


class FindingStatusUpdatePayload(BaseModel):
    status: Literal["approved", "rejected"] = Field(..., examples=["approved"])
    reviewer_label: str = Field(..., min_length=2, max_length=120)
    rationale: str = Field(..., min_length=5, max_length=4000)


@router.post(
    "/cases/{id}/analyze",
    summary="Run Role 2 analysis and store the findings",
)
def analyze_case(id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Run intelligence analysis on all case events and store schema-compliant findings."""
    case = db.query(Case).filter(Case.case_id == id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{id}' not found",
        )

    events = db.query(EventModel).filter(EventModel.case_id == id).all()
    events_payload = [e.to_dict() for e in events]

    findings_data = execute_analyze(events_payload, case_id=id)

    # T3/T6/T7/T8: Create immutable analysis run if ACTIVE evidence exists
    manifest = manifest_evidence(db, id)
    run_id = None
    claims_count = 0
    if manifest:
        assumptions = {"case_timezone": os.getenv("PRAMANA_INTEL_TIMEZONE", "UTC")}
        run_res = execute_analysis_run(
            db,
            case_id=id,
            engine_version="pramana-engine@1.0.0",
            assumptions=assumptions,
        )
        run_id = run_res["run_id"]
        claims_count = run_res["claims_count"]

    created_count = 0
    for f in findings_data:
        existing = db.query(FindingModel).filter(FindingModel.finding_id == f["finding_id"]).first()
        if not existing:
            finding_row = FindingModel(
                finding_id=f["finding_id"],
                case_id=id,
                type=f["type"],
                claim=f["claim"],
                confidence=f["confidence"],
                evidence_event_ids=f.get("evidence_event_ids", []),
                reasoning=f.get("reasoning"),
                alternatives=f.get("alternatives"),
                needs_human_review=f.get("needs_human_review", True),
                status=f.get("status", "pending"),
            )
            db.add(finding_row)
            created_count += 1

    db.commit()

    return {
        "findings_created": created_count,
        "run_id": run_id,
        "claims_created": claims_count,
    }


@router.get(
    "/cases/{id}/findings",
    summary="List findings",
)
def list_case_findings(id: str, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """Retrieve all findings for a given case."""
    case = db.query(Case).filter(Case.case_id == id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{id}' not found",
        )

    findings = (
        db.query(FindingModel)
        .filter(FindingModel.case_id == id)
        .order_by(FindingModel.created_at.desc())
        .all()
    )
    return [f.to_dict() for f in findings]


@router.patch(
    "/findings/{id}",
    summary="Append an investigator review decision",
)
def update_finding_status(
    id: str,
    payload: FindingStatusUpdatePayload,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Append a review decision. Reviewer labels are self-declared, not authenticated identities."""
    finding = db.query(FindingModel).filter(FindingModel.finding_id == id).first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding '{id}' not found")

    reviewer = payload.reviewer_label.strip()
    rationale = payload.rationale.strip()
    if len(reviewer) < 2 or len(rationale) < 5:
        raise HTTPException(status_code=422, detail="Reviewer label and rationale must contain meaningful text")

    decision = FindingReviewDecision(
        review_id=f"REV-{uuid.uuid4().hex.upper()}",
        finding_id=id,
        decision=payload.status,
        reviewer_label=reviewer,
        reviewer_identity_type="self_declared",
        rationale=rationale,
    )
    db.add(decision)
    finding.status = payload.status
    db.commit()
    db.refresh(decision)
    return {"finding_id": finding.finding_id, "status": finding.status, "review": decision.to_dict()}


@router.get("/findings/{id}/reviews", summary="Append-only review decision history")
def list_finding_reviews(id: str, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    finding = db.query(FindingModel).filter(FindingModel.finding_id == id).first()
    if not finding:
        raise HTTPException(status_code=404, detail=f"Finding '{id}' not found")
    rows = (db.query(FindingReviewDecision)
            .filter(FindingReviewDecision.finding_id == id)
            .order_by(FindingReviewDecision.decided_at.asc(), FindingReviewDecision.review_id.asc())
            .all())
    return [row.to_dict() for row in rows]


@router.get(
    "/findings/{id}/lineage",
    summary="Finding, then events, evidence and SHA-256",
)
def get_finding_lineage_endpoint(id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve cryptographic and artifact lineage for a specific finding."""
    lineage = get_finding_lineage(db, id)
    if not lineage:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{id}' not found",
        )
    return lineage
