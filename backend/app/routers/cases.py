"""Role 3: Cases router.

Endpoints:
- POST /cases: Create a new investigation case
- GET /cases/{id}: Retrieve case details
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.models import Case
from app.db.session import get_db

router = APIRouter(tags=["cases"])


class CaseCreateRequest(BaseModel):
    name: str = Field(..., examples=["Case 001"])
    case_id: str | None = Field(None, examples=["CASE-001"])


class CaseResponse(BaseModel):
    case_id: str
    name: str


@router.post(
    "/cases",
    response_model=CaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a case",
)
def create_case(payload: CaseCreateRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Create a new forensic case."""
    case_id = payload.case_id or f"CASE-{uuid.uuid4().hex[:6].upper()}"

    existing = db.query(Case).filter(Case.case_id == case_id).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Case with ID '{case_id}' already exists",
        )

    case = Case(case_id=case_id, name=payload.name)
    db.add(case)
    db.commit()
    db.refresh(case)

    return {"case_id": case.case_id, "name": case.name}


@router.get("/cases/{id}", summary="Get case metadata")
def get_case(id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve case by ID."""
    case = db.query(Case).filter(Case.case_id == id).first()
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{id}' not found")
    return case.to_dict()
