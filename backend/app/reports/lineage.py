"""Role 3: Trace finding lineage to events, evidence files, and SHA-256 hashes."""
from __future__ import annotations

from typing import Any
from sqlalchemy.orm import Session

from app.db.models import EventModel, Evidence, FindingModel


def get_finding_lineage(db: Session, finding_id: str) -> dict[str, Any] | None:
    """Walk a finding back to its cited events, parent evidence items, and SHA-256 hashes.
    
    Returns None if the finding does not exist.
    """
    finding = db.query(FindingModel).filter(FindingModel.finding_id == finding_id).first()
    if not finding:
        return None

    event_ids: list[str] = finding.evidence_event_ids or []

    # Retrieve referenced events
    events: list[EventModel] = []
    if event_ids:
        events = db.query(EventModel).filter(EventModel.event_id.in_(event_ids)).all()

    # Collect unique evidence IDs
    evidence_ids = sorted(list({ev.evidence_id for ev in events if ev.evidence_id}))

    # Retrieve source evidence files
    evidence_items: list[Evidence] = []
    if evidence_ids:
        evidence_items = db.query(Evidence).filter(Evidence.evidence_id.in_(evidence_ids)).all()

    return {
        "finding_id": finding.finding_id,
        "events": [
            {
                "event_id": ev.event_id,
                "artifact_ref": ev.artifact_ref,
                "evidence_id": ev.evidence_id,
            }
            for ev in events
        ],
        "evidence": [
            {
                "evidence_id": item.evidence_id,
                "filename": item.filename,
                "sha256": item.sha256,
            }
            for item in evidence_items
        ],
    }
