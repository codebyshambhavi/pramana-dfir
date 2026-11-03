"""Role 3 / T4: evidence integrity and tamper detection.

Endpoints:
- POST /evidence/{id}/verify: re-hash the stored file; mismatch -> QUARANTINED
- POST /evidence/{id}/remove: soft removal (status REMOVED); nothing is deleted
- GET /cases/{id}/integrity: read-only integrity summary of a case
- POST /evidence/{id}/simulate-tamper: DEMO ONLY, enabled by DEMO_MODE=1

Every evidence state change appends one custody entry in the same transaction.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.models import Case, Evidence
from app.db.session import (
    EvidenceStateError,
    append_custody_record,
    case_integrity,
    get_db,
    hash_stored_file,
    remove_evidence,
    verify_evidence,
)

router = APIRouter(tags=["integrity"])

DEMO_TAMPER_BYTES = b"\n# PRAMANA DEMO: simulated tamper\n"


class VerifyRequest(BaseModel):
    actor: str = Field("Integrity Verifier", min_length=1, max_length=128)


class RemoveRequest(BaseModel):
    actor: str = Field("Investigator", min_length=1, max_length=128)
    reason: str | None = Field(None, max_length=512, examples=["Duplicate of EVID-002"])


def _demo_mode() -> bool:
    return os.getenv("DEMO_MODE", "0").strip() == "1"


def _not_found(evidence_id: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence '{evidence_id}' not found")


@router.post("/evidence/{id}/verify", summary="Re-hash the stored file and compare with the intake SHA-256")
def verify_evidence_endpoint(
    id: str,
    payload: VerifyRequest | None = None,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    actor = (payload or VerifyRequest()).actor
    try:
        result = verify_evidence(db, id, actor=actor)
        db.commit()
    except LookupError as exc:
        db.rollback()
        raise _not_found(id) from exc
    except Exception:
        db.rollback()
        raise
    return result


@router.post("/evidence/{id}/remove", summary="Soft-remove evidence (status REMOVED; nothing is deleted)")
def remove_evidence_endpoint(
    id: str,
    payload: RemoveRequest | None = None,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    body = payload or RemoveRequest()
    try:
        result = remove_evidence(db, id, actor=body.actor, reason=body.reason)
        db.commit()
    except LookupError as exc:
        db.rollback()
        raise _not_found(id) from exc
    except EvidenceStateError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except Exception:
        db.rollback()
        raise
    return result


@router.get("/cases/{id}/integrity", summary="Integrity summary of a case (read-only)")
def get_case_integrity(id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    if db.get(Case, id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Case '{id}' not found")
    return case_integrity(db, id)


@router.post(
    "/evidence/{id}/simulate-tamper",
    summary="DEMO ONLY: append bytes to the stored file (requires DEMO_MODE=1)",
)
def simulate_tamper(id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Modify the stored copy so a following verify detects tampering.

    Disabled (404) unless DEMO_MODE=1. Does not change status; POST /verify does.
    Records a DEMO custody entry so the demo itself is part of the record.
    """
    if not _demo_mode():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")
    evidence = db.get(Evidence, id)
    if evidence is None:
        raise _not_found(id)
    path = Path(evidence.stored_path) if evidence.stored_path else None
    if path is None or not path.is_file():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Stored evidence file is missing")

    with path.open("ab") as handle:
        handle.write(DEMO_TAMPER_BYTES)
    tampered_sha256 = hash_stored_file(str(path))

    try:
        entry = append_custody_record(
            db=db,
            evidence_id=id,
            actor="DEMO_MODE",
            action="DEMO: simulated tamper of stored file",
            sha256=tampered_sha256,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {
        "evidence_id": id,
        "demo": True,
        "intake_sha256": evidence.sha256,
        "tampered_sha256": tampered_sha256,
        "status": evidence.status,
        "custody_entry": entry.to_dict(),
    }
