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

from app.db.models import Case, Entity, EventModel, Evidence, utc_now
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
    case = db.query(Case).filter(Case.case_id == id).with_for_update().first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case '{id}' not found",
        )
    if case.status == CASE_STATUS_CLOSED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Case '{id}' is closed; reopen it before adding evidence",
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
    existing_ids = [row[0] for row in db.query(Evidence.evidence_id).all()]
    numeric_ids = []
    for existing_id in existing_ids:
        match = re.fullmatch(r"EVID-(\d+)", existing_id or "")
        if match:
            numeric_ids.append(int(match.group(1)))
    next_number = max(numeric_ids, default=0) + 1
    evidence_id = f"EVID-{next_number:03d}"
    while db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first() is not None:
        next_number += 1
        evidence_id = f"EVID-{next_number:03d}"

    intake_time = utc_now()
    evidence_record = Evidence(
        evidence_id=evidence_id,
        case_id=id,
        filename=safe_basename,
        sha256=sha256,
        size_bytes=size_bytes,
        intake_time=intake_time,
        stored_path=str(stored_path),
        source_type=(safe_basename.rsplit(".", 1)[-1].lower() if "." in safe_basename else "unknown"),
        source_identifier=safe_basename,
        acquisition_method="uploaded_file",
        acquired_by="Investigator (System Intake)",
        parse_status=None,
        parser_warnings=[],
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
        parser_warnings: list[str] = []
        pst_attachment_result: dict[str, Any] | None = None

        if stored_path.suffix.lower() == ".pst":
            import sys
            evidence_engine_dir = str(Path(__file__).resolve().parents[3] / "evidence-engine")
            if evidence_engine_dir not in sys.path:
                sys.path.insert(0, evidence_engine_dir)
            from parsers.pst import extract_pst_attachments

            attachment_dir = (UPLOAD_DIR.resolve() / id / "pst-attachments" / evidence_id)
            pst_attachment_result = extract_pst_attachments(
                str(stored_path),
                str(attachment_dir),
                parent_evidence_id=evidence_id,
            )
            parser_warnings.extend(pst_attachment_result["warnings"])
            evidence_record.parse_status = pst_attachment_result["status"]
            evidence_record.parser_warnings = parser_warnings
            evidence_record.parser_name = pst_attachment_result["parser_name"]
            evidence_record.parser_version = pst_attachment_result["parser_version"]
            evidence_record.source_locator = safe_basename

            existing_ids = [row[0] for row in db.query(Evidence.evidence_id).all()]
            numeric_ids = []
            for existing_id in existing_ids:
                match = re.fullmatch(r"EVID-(\d+)", existing_id or "")
                if match:
                    numeric_ids.append(int(match.group(1)))
            next_attachment_number = max(numeric_ids, default=0) + 1

            for attachment in pst_attachment_result["attachments"]:
                if attachment["status"] not in ("ACQUIRED", "EMPTY"):
                    continue
                attachment_id = f"EVID-{next_attachment_number:03d}"
                while db.query(Evidence).filter(Evidence.evidence_id == attachment_id).first() is not None:
                    next_attachment_number += 1
                    attachment_id = f"EVID-{next_attachment_number:03d}"
                next_attachment_number += 1

                attachment_record = Evidence(
                    evidence_id=attachment_id,
                    case_id=id,
                    filename=attachment["filename"],
                    sha256=attachment["sha256"],
                    size_bytes=attachment["byte_size"],
                    intake_time=utc_now(),
                    stored_path=attachment["stored_path"],
                    source_type="pst_attachment",
                    source_identifier=attachment["attachment_id"],
                    acquisition_method="pst_attachment_extraction",
                    acquired_by="Investigator (System Intake)",
                    parser_name=pst_attachment_result["parser_name"],
                    parser_version=pst_attachment_result["parser_version"],
                    parse_status=attachment["status"],
                    parser_warnings=[],
                    source_locator=attachment["message_locator"],
                    parent_evidence_id=evidence_id,
                )
                db.add(attachment_record)
                db.flush()
                append_custody_record(
                    db=db,
                    evidence_id=attachment_id,
                    actor="Investigator (System Intake)",
                    action="PST Attachment Acquisition & SHA-256 Hash Verification",
                    sha256=attachment["sha256"],
                    time_val=utc_now(),
                    previous_state=None,
                    new_state="ACTIVE",
                    reason=(
                        f"PST parent={evidence_id}; "
                        f"message={attachment['message_id']}; "
                        f"folder={attachment['folder_path']}; "
                        f"attachment={attachment['attachment_id']}"
                    ),
                )

        # Store parsed events
        seen_entity_ids: set[str] = set()
        for ev in parsed_events:
            # Events are schema-validated, so "timestamp" is always present and
            # RFC 3339. An unparseable value is an error, never replaced by the
            # intake time (that would silently invent an event time).
            ts_dt = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))

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
                artifact_ref=ev["artifact_ref"],
                sha256=sha256,
                timestamp=ts_dt,
                source=ev["source"],
                device=ev.get("device"),
                actor=ev.get("actor"),
                action=ev["action"],
                object=ev.get("object"),
                ip=ev.get("ip"),
                location=ev.get("location"),
                raw=ev.get("raw"),
                parser_version=ev.get("parser_version"),
                tz_assumption=ev.get("tz_assumption"),
                family=ev.get("family"),
            )
            db.add(event_row)

            import sys
            evidence_engine_dir = str(Path(__file__).resolve().parents[3] / "evidence-engine")
            if evidence_engine_dir not in sys.path:
                sys.path.insert(0, evidence_engine_dir)
            from parsers.normalization import extract_entities
            entity_values = [
                ev.get("actor"),
                ev.get("object"),
                ev.get("ip"),
                ev.get("raw"),
            ]
            for entity in extract_entities(*entity_values):
                entity_id = hashlib.sha256(
                    f"{id}|{evidence_id}|{entity['entity_type']}|{entity['canonical_value']}".encode()
                ).hexdigest()[:16]
                if entity_id in seen_entity_ids:
                    continue
                seen_entity_ids.add(entity_id)
                db.add(Entity(
                    entity_id=entity_id,
                    case_id=id,
                    evidence_id=evidence_id,
                    entity_type=entity["entity_type"],
                    canonical_value=entity["canonical_value"],
                    aliases=entity["aliases"],
                    normalisation_method=entity["normalisation_method"],
                    confidence=entity["confidence"],
                ))

        # If we got here without exception, commit the transaction
        db.commit()

    except ValueError as exc:
        # The evidence is unsupported or malformed. Nothing is stored: roll back
        # the database and remove the file written above, then say why.
        db.rollback()
        stored_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=422,
            detail=f"Evidence rejected: {exc}",
        ) from exc
    except Exception:
        # Any other failure: roll back all pending changes (atomicity), drop the
        # orphaned file, and re-raise unchanged.
        db.rollback()
        stored_path.unlink(missing_ok=True)
        raise

    return {
        "evidence_id": evidence_id,
        "filename": safe_basename,
        "sha256": sha256,
        "events_created": len(parsed_events),
        "parse_status": (
            pst_attachment_result["status"]
            if pst_attachment_result is not None
            else "SUCCESS"
        ),
        "parser_warnings": (
            pst_attachment_result["warnings"]
            if pst_attachment_result is not None
            else []
        ),
        "attachment_count": (
            len(pst_attachment_result["attachments"])
            if pst_attachment_result is not None
            else 0
        ),
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