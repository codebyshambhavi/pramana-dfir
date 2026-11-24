"""Role 3: Graph router.

Endpoint:
- GET /cases/{id}/graph: Nodes and edges representing relationships between entities
"""
from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.models import Case, EVIDENCE_ACTIVE, Evidence, EventModel
from app.db.session import get_db
from app.graph.builder import build_graph

router = APIRouter(tags=["graph"])


@router.get(
    "/cases/{id}/graph",
    summary="Nodes and edges for the graph view",
)
def get_case_graph(id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Retrieve NetworkX-constructed nodes and edges for the forensic evidence graph."""
    case = db.query(Case).filter(Case.case_id == id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{id}' not found",
        )

    # Only ACTIVE evidence contributes to the current graph.
    # Removed evidence and its events remain stored for forensic history.
    events = (
        db.query(EventModel)
        .join(Evidence, EventModel.evidence_id == Evidence.evidence_id)
        .filter(
            EventModel.case_id == id,
            Evidence.case_id == id,
            Evidence.status == EVIDENCE_ACTIVE,
        )
        .all()
    )
    events_payload = [e.to_dict() for e in events]

    graph_data = build_graph(events_payload)
    return graph_data
