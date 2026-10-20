"""Role 3: Evidence and Events router.

Endpoints:
- POST /cases/{id}/evidence: Upload file, compute SHA-256, record custody, parse events
- GET /cases/{id}/evidence: List evidence items with SHA-256 hashes and custody log
- GET /cases/{id}/events: Filterable query of events by time range and source
"""
from __future__ import annotations

import hashlib
import os
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.db.models import Case, EventModel, Evidence, utc_now
from app.db.session import append_custody_record, get_db
from app.services.pipeline import execute_parse_evidence

router = APIRouter(tags=["evidence"])

UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./data/uploads"))


@router.post(
    "/cases/{id}/evidence",
    status_code=status.HTTP_201_CREATED,
    summary="Upload a file, hash it, parse it, return its evidence ID",
)
async def upload_evidence(
    id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Upload evidence file, compute cryptographic hash, log custody, and parse events."""
    case = db.query(Case).filter(Case.case_id == id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{id}' not found",
        )

    # Read uploaded content and calculate SHA-256
    content = await file.read()
    sha256 = hashlib.sha256(content).hexdigest()
    size_bytes = len(content)

    # Sanitize filename and prevent path traversal
    raw_filename = Path(file.filename or "unknown").name
    safe_basename = re.sub(r"[^a-zA-Z0-9_.-]", "_", raw_filename) or "evidence.bin"

    # Persist file to storage directory safely
    target_dir = UPLOAD_DIR.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    stored_filename = f"{id}_{uuid.uuid4().hex[:6]}_{safe_basename}"
    stored_path = (target_dir / stored_filename).resolve()
    if not str(stored_path).startswith(str(target_dir)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename: potential path traversal detected",
        )
    stored_path.write_bytes(content)

    # Generate sequential or unique evidence ID (globally unique)
    count = db.query(Evidence).count()
    evidence_id = f"EVID-{count + 1:03d}"

    intake_time = utc_now()
    evidence_record = Evidence(
        evidence_id=evidence_id,
        case_id=id,
        filename=safe_basename,
        sha256=sha256,
        size_bytes=size_bytes,
        intake_time=intake_time,
        stored_path=str(stored_path),
    )

    try:
        db.add(evidence_record)
        # Append acquisition record to custody chain
        append_custody_record(
            db=db,
            evidence_id=evidence_id,
            actor="Investigator (System Intake)",
            action="Evidence Acquisition & SHA-256 Hash Verification",
            sha256=sha256,
            time_val=intake_time,
        )

        # Parse evidence into normalized events
        parsed_events = execute_parse_evidence(
            path=str(stored_path),
            case_id=id,
            evidence_id=evidence_id,
            sha256=sha256,
        )

        # Store parsed events
        for ev in parsed_events:
            ts_str = ev.get("timestamp")
            ts_dt = intake_time
            if ts_str:
                try:
                    clean_ts = ts_str.replace("Z", "+00:00")
                    ts_dt = datetime.fromisoformat(clean_ts)
                except Exception:
                    ts_dt = intake_time

            stored_event_id = (
                hashlib.sha256(
                    f"{id}|{evidence_id}|{ev['event_id']}".encode()
                ).hexdigest()[:16]
                + f":{ev['event_id']}"
            )

            event_row = EventModel(
                event_id=stored_event_id,
                case_id=id,
                evidence_id=evidence_id,
                artifact_ref=ev.get("artifact_ref", f"{file.filename}#byte=0"),
                sha256=sha256,
                timestamp=ts_dt,
                source=ev.get("source", "log"),
                device=ev.get("device"),
                actor=ev.get("actor"),
                action=ev.get("action", "unknown"),
                object=ev.get("object"),
                ip=ev.get("ip"),
                location=ev.get("location"),
                raw=ev.get("raw"),
            )
            db.add(event_row)

        # If we got here without exception, commit the transaction
        db.commit()

    except Exception:
        # If any exception occurred, roll back all pending changes to maintain atomicity
        db.rollback()
        raise

    return {
        "evidence_id": evidence_id,
        "filename": safe_basename,
        "sha256": sha256,
        "events_created": len(parsed_events),
    }


@router.get(
    "/cases/{id}/evidence",
    summary="List evidence with hashes and custody log",
)
def list_case_evidence(id: str, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """Retrieve all evidence registered for a case including custody logs."""
    case = db.query(Case).filter(Case.case_id == id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{id}' not found",
        )

    evidence_items = (
        db.query(Evidence)
        .filter(Evidence.case_id == id)
        .order_by(Evidence.intake_time.asc())
        .all()
    )
    return [ev.to_dict() for ev in evidence_items]


@router.get(
    "/cases/{id}/events",
    summary="Events, filterable by time range and source",
)
def list_case_events(
    id: str,
    from_time: str | None = Query(None, alias="from"),
    to_time: str | None = Query(None, alias="to"),
    source: str | None = Query(None),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """Retrieve events for a case, with optional timestamp and source filtering."""
    case = db.query(Case).filter(Case.case_id == id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{id}' not found",
        )

    query = db.query(EventModel).filter(EventModel.case_id == id)

    if source:
        query = query.filter(EventModel.source == source)

    if from_time:
        try:
            from_dt = datetime.fromisoformat(from_time.replace("Z", "+00:00"))
            query = query.filter(EventModel.timestamp >= from_dt)
        except ValueError:
            pass

    if to_time:
        try:
            to_dt = datetime.fromisoformat(to_time.replace("Z", "+00:00"))
            query = query.filter(EventModel.timestamp <= to_dt)
        except ValueError:
            pass

    events = query.order_by(EventModel.timestamp.asc()).all()
    return [ev.to_dict() for ev in events]