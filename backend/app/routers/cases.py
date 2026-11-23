"""Role 3: Cases router.

Endpoints:
- POST /cases: Create a new investigation case
- GET /cases: List cases with evidence/finding/run counts
- GET /cases/{id}: Retrieve case details
- PATCH /cases/{id}: Edit case metadata (title, description, scope, tags, owner)
- POST /cases/{id}/close: Close a case (no new evidence is accepted)
- POST /cases/{id}/reopen: Reopen a closed case (status REOPENED)

A case must exist before evidence can be uploaded to it; every evidence item, event, finding and run
carries its case_id.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.models import (
    CASE_STATUS_CLOSED,
    CASE_STATUS_OPEN,
    EVIDENCE_ACTIVE,
    AnalysisRun,
    Case,
    Evidence,
    FindingModel,
    utc_now,
)
from app.db.session import get_db

router = APIRouter(tags=["cases"])

CASE_STATUS_REOPENED = "REOPENED"
MAX_TAGS = 20


def _clean_tags(tags: list[str] | None) -> list[str] | None:
    if tags is None:
        return None
    cleaned: list[str] = []
    for tag in tags:
        value = tag.strip()
        if value and value not in cleaned:
            cleaned.append(value[:64])
    if len(cleaned) > MAX_TAGS:
        raise ValueError(f"At most {MAX_TAGS} tags are allowed")
    return cleaned


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip()
    return value or None


class CaseCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, examples=["Laptop data exfiltration"])
    case_id: str | None = Field(None, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", examples=["CASE-001"])
    description: str | None = Field(None, max_length=4000)
    scope: str | None = Field(None, max_length=4000)
    tags: list[str] | None = None
    owner: str | None = Field(None, max_length=255, examples=["Investigator name (self-declared)"])

    @field_validator("name")
    @classmethod
    def _name_not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Case title must not be blank")
        return value

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: list[str] | None) -> list[str] | None:
        return _clean_tags(value)


class CaseUpdateRequest(BaseModel):
    """Only the fields present in the request are changed. case_id, status and timestamps cannot be edited here."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = Field(None, max_length=4000)
    scope: str | None = Field(None, max_length=4000)
    tags: list[str] | None = None
    owner: str | None = Field(None, max_length=255)

    @field_validator("name")
    @classmethod
    def _name_not_blank(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("Case title must not be blank")
        return value

    @field_validator("tags")
    @classmethod
    def _tags(cls, value: list[str] | None) -> list[str] | None:
        return _clean_tags(value)


def _get_case_or_404(db: Session, case_id: str) -> Case:
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{case_id}' not found")
    return case


def _counts(db: Session, case_ids: list[str] | None = None) -> dict[str, dict[str, int]]:
    """Active evidence, finding and run counts per case, computed in the database."""
    summary: dict[str, dict[str, int]] = {}
    sources = (
        ("evidence_count", Evidence, Evidence.evidence_id, Evidence.status == EVIDENCE_ACTIVE),
        ("finding_count", FindingModel, FindingModel.finding_id, None),
        ("run_count", AnalysisRun, AnalysisRun.run_id, None),
    )
    for key, model, pk, condition in sources:
        query = db.query(model.case_id, func.count(pk))
        if condition is not None:
            query = query.filter(condition)
        if case_ids is not None:
            query = query.filter(model.case_id.in_(case_ids))
        for case_id, count in query.group_by(model.case_id).all():
            summary.setdefault(case_id, {})[key] = int(count)
    return summary


def _with_counts(case: Case, counts: dict[str, dict[str, int]]) -> dict[str, Any]:
    data = case.to_dict()
    case_counts = counts.get(case.case_id, {})
    data["evidence_count"] = case_counts.get("evidence_count", 0)
    data["finding_count"] = case_counts.get("finding_count", 0)
    data["run_count"] = case_counts.get("run_count", 0)
    return data


@router.post(
    "/cases",
    status_code=status.HTTP_201_CREATED,
    summary="Create a case",
)
def create_case(payload: CaseCreateRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Create a new forensic case. A case_id is generated when none is supplied."""
    case_id = payload.case_id or f"CASE-{uuid.uuid4().hex[:6].upper()}"

    existing = db.query(Case).filter(Case.case_id == case_id).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Case with ID '{case_id}' already exists",
        )

    case = Case(
        case_id=case_id,
        name=payload.name,
        description=_clean_text(payload.description),
        scope=_clean_text(payload.scope),
        tags=payload.tags or [],
        owner=_clean_text(payload.owner),
        status=CASE_STATUS_OPEN,
    )
    db.add(case)
    db.commit()
    db.refresh(case)

    return _with_counts(case, {})


@router.get("/cases", summary="List cases with evidence, finding and run counts")
def list_cases(
    status_filter: str | None = Query(None, alias="status", description="Only cases with this status, e.g. OPEN or CLOSED"),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """All cases, newest first. Counts are computed per case on the server."""
    query = db.query(Case)
    if status_filter:
        query = query.filter(Case.status == status_filter.upper())
    cases = query.order_by(Case.created_at.desc(), Case.case_id).all()
    counts = _counts(db, [case.case_id for case in cases]) if cases else {}
    return [_with_counts(case, counts) for case in cases]


@router.get("/cases/{id}", summary="Get case metadata")
def get_case(id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve case by ID, with its evidence, finding and run counts."""
    case = _get_case_or_404(db, id)
    return _with_counts(case, _counts(db, [case.case_id]))


@router.patch("/cases/{id}", summary="Edit case metadata")
def update_case(id: str, payload: CaseUpdateRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Change title, description, scope, tags or owner. Closed cases must be reopened first."""
    case = _get_case_or_404(db, id)
    if case.status == CASE_STATUS_CLOSED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Case '{id}' is closed; reopen it before editing")

    changes = payload.model_dump(exclude_unset=True)
    if "name" in changes:
        if changes["name"] is None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Case title must not be blank")
        case.name = changes["name"]
    if "description" in changes:
        case.description = _clean_text(changes["description"])
    if "scope" in changes:
        case.scope = _clean_text(changes["scope"])
    if "tags" in changes:
        case.tags = changes["tags"] or []
    if "owner" in changes:
        case.owner = _clean_text(changes["owner"])
    if changes:
        case.updated_at = utc_now()

    db.commit()
    db.refresh(case)
    return _with_counts(case, _counts(db, [case.case_id]))


@router.post("/cases/{id}/close", summary="Close a case; no further evidence is accepted")
def close_case(id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    case = _get_case_or_404(db, id)
    if case.status == CASE_STATUS_CLOSED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Case '{id}' is already closed")
    now = utc_now()
    case.status = CASE_STATUS_CLOSED
    case.closed_at = now
    case.updated_at = now
    db.commit()
    db.refresh(case)
    return _with_counts(case, _counts(db, [case.case_id]))


@router.post("/cases/{id}/reopen", summary="Reopen a closed case (status REOPENED)")
def reopen_case(id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    case = _get_case_or_404(db, id)
    if case.status != CASE_STATUS_CLOSED:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Case '{id}' is not closed")
    case.status = CASE_STATUS_REOPENED
    case.closed_at = None
    case.updated_at = utc_now()
    db.commit()
    db.refresh(case)
    return _with_counts(case, _counts(db, [case.case_id]))
