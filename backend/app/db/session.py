"""Role 3: Database engine, session management, and custody service."""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.migrate import migrate
from app.db.models import (
    EVIDENCE_ACTIVE,
    EVIDENCE_QUARANTINED,
    EVIDENCE_REMOVED,
    EVIDENCE_STATUSES,
    VERIFY_CUSTODY_BROKEN,
    VERIFY_MATCH,
    VERIFY_MISMATCH,
    VERIFY_MISSING,
    VERIFY_STATES,
    CustodyEntry,
    Evidence,
    compute_entry_hash,
    utc_now,
)

# Recorded as the custody sha256 when the stored file cannot be read at all.
NO_FILE_SHA256 = "0" * 64
_CUSTODY_ACTION_MAX = 128

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./pramana.db")

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db(target_engine=None) -> None:
    """Create missing tables and add missing columns (additive only; see app.db.migrate)."""
    eng = target_engine or engine
    migrate(eng)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency to yield database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def format_custody_time(time_val: Any) -> str:
    """Standardize datetime to ISO UTC string for consistent cryptographic hashing."""
    if isinstance(time_val, datetime):
        return time_val.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(time_val, str):
        cleaned = time_val.replace("+00:00", "Z")
        if not cleaned.endswith("Z"):
            cleaned = f"{cleaned}Z"
        return cleaned
    return str(time_val or "")


def append_custody_record(
    db: Session,
    evidence_id: str,
    actor: str,
    action: str,
    sha256: str,
    time_val: datetime | None = None,
) -> CustodyEntry:
    """Append a cryptographically hash-chained entry to the custody log.
    
    Previous hash is the entry_hash of the latest entry for this evidence,
    or 64 zeros for the genesis acquisition entry.
    """
    last_entry = (
        db.query(CustodyEntry)
        .filter(CustodyEntry.evidence_id == evidence_id)
        .order_by(CustodyEntry.id.desc())
        .first()
    )

    prev_hash = last_entry.entry_hash if last_entry else ("0" * 64)
    record_time = time_val or utc_now()
    time_iso = format_custody_time(record_time)

    entry_hash = compute_entry_hash(
        prev_hash=prev_hash,
        evidence_id=evidence_id,
        actor=actor,
        action=action,
        time_iso=time_iso,
        sha256=sha256,
    )

    entry = CustodyEntry(
        evidence_id=evidence_id,
        actor=actor,
        action=action,
        time=record_time,
        sha256=sha256,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )
    db.add(entry)
    db.flush()  # Flush to get the ID without committing
    db.refresh(entry)
    return entry


def verify_custody_log(db: Session, evidence_id: str) -> tuple[bool, str]:
    """Verify that the custody log for an evidence item has not been tampered with.
    
    Returns (is_valid, message).
    """
    entries = (
        db.query(CustodyEntry)
        .filter(CustodyEntry.evidence_id == evidence_id)
        .order_by(CustodyEntry.id.asc())
        .all()
    )
    if not entries:
        return True, "No custody records found."

    expected_prev = "0" * 64
    for idx, entry in enumerate(entries):
        if entry.prev_hash != expected_prev:
            return False, f"Broken chain at index {idx}: expected prev_hash {expected_prev}, got {entry.prev_hash}"

        recomputed = compute_entry_hash(
            prev_hash=entry.prev_hash,
            evidence_id=entry.evidence_id,
            actor=entry.actor,
            action=entry.action,
            time_iso=format_custody_time(entry.time),
            sha256=entry.sha256,
        )
        if recomputed != entry.entry_hash:
            return False, f"Tampered entry hash at index {idx}: expected {recomputed}, recorded {entry.entry_hash}"

        expected_prev = entry.entry_hash

    return True, "Custody chain intact and cryptographically verified."


# -------------------------------------------------------------------------
# T4: evidence integrity
# -------------------------------------------------------------------------


class EvidenceStateError(ValueError):
    """The requested evidence state change is not allowed from the current status."""


def hash_stored_file(path: str | None, chunk_size: int = 1024 * 1024) -> str | None:
    """Stream the SHA-256 of the stored evidence file. Returns None if it is missing or unreadable."""
    if not path:
        return None
    file_path = Path(path)
    if not file_path.is_file():
        return None
    digest = hashlib.sha256()
    try:
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(chunk_size), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def _custody_action(text: str) -> str:
    return text if len(text) <= _CUSTODY_ACTION_MAX else text[: _CUSTODY_ACTION_MAX - 3] + "..."


def _get_evidence(db: Session, evidence_id: str) -> Evidence:
    evidence = db.get(Evidence, evidence_id)
    if evidence is None:
        raise LookupError(f"Evidence '{evidence_id}' not found")
    return evidence


def verify_evidence(db: Session, evidence_id: str, actor: str = "Integrity Verifier") -> dict[str, Any]:
    """Re-hash the stored file, compare it with the intake SHA-256, and record the result.

    `verify_state` records the outcome; `status` changes only on failure:
    - MATCH: file hash equals the intake hash and the custody chain is intact.
      `status` is unchanged and `verified_at` is set. A later match does not
      clear a quarantine.
    - MISMATCH (file changed), MISSING (file gone or unreadable) or
      CUSTODY_BROKEN (custody chain fails verification): `status` becomes
      QUARANTINED, including previously REMOVED evidence (H″: a mismatch
      quarantines evidence).

    Every call appends one custody entry. Its sha256 is the hash actually
    observed (zeros if no file), so the chain records what was found. The
    intake hash on the evidence row is never changed. Flushes, does not commit.
    """
    evidence = _get_evidence(db, evidence_id)
    chain_ok, chain_message = verify_custody_log(db, evidence_id)
    observed = hash_stored_file(evidence.stored_path)
    previous = evidence.status or EVIDENCE_ACTIVE

    if observed is None:
        outcome = VERIFY_MISSING
    elif observed != evidence.sha256:
        outcome = VERIFY_MISMATCH
    elif not chain_ok:
        outcome = VERIFY_CUSTODY_BROKEN
    else:
        outcome = VERIFY_MATCH

    now = utc_now()
    if outcome == VERIFY_MATCH:
        new_status = previous
        evidence.verified_at = now
    else:
        new_status = EVIDENCE_QUARANTINED
    evidence.status = new_status
    evidence.verify_state = outcome

    entry = append_custody_record(
        db=db,
        evidence_id=evidence_id,
        actor=actor,
        action=_custody_action(f"Integrity verification: {outcome} ({previous} -> {new_status})"),
        sha256=observed or NO_FILE_SHA256,
        time_val=now,
    )
    return {
        "evidence_id": evidence_id,
        "outcome": outcome,
        "match": outcome == VERIFY_MATCH,
        "verify_state": outcome,
        "previous_status": previous,
        "status": new_status,
        "intake_sha256": evidence.sha256,
        "observed_sha256": observed,
        "custody_chain_valid": chain_ok,
        "custody_message": chain_message,
        "verified_at": evidence.verified_at.isoformat() if evidence.verified_at else None,
        "custody_entry": entry.to_dict(),
    }


def remove_evidence(
    db: Session,
    evidence_id: str,
    actor: str = "Investigator",
    reason: str | None = None,
) -> dict[str, Any]:
    """Soft-remove evidence: status becomes REMOVED. The row, stored file and hashes stay.

    Appends one custody entry. Raises EvidenceStateError if already REMOVED.
    Flushes, does not commit.
    """
    evidence = _get_evidence(db, evidence_id)
    previous = evidence.status or EVIDENCE_ACTIVE
    if previous == EVIDENCE_REMOVED:
        raise EvidenceStateError(f"Evidence '{evidence_id}' is already REMOVED")

    evidence.status = EVIDENCE_REMOVED
    action = f"Evidence removed ({previous} -> {EVIDENCE_REMOVED})"
    if reason and reason.strip():
        action += f": {reason.strip()}"
    entry = append_custody_record(
        db=db,
        evidence_id=evidence_id,
        actor=actor,
        action=_custody_action(action),
        sha256=evidence.sha256,
    )
    return {
        "evidence_id": evidence_id,
        "previous_status": previous,
        "status": EVIDENCE_REMOVED,
        "custody_entry": entry.to_dict(),
    }


def case_integrity(db: Session, case_id: str) -> dict[str, Any]:
    """Read-only integrity summary of a case. Does not re-hash files or write custody."""
    items = (
        db.query(Evidence)
        .filter(Evidence.case_id == case_id)
        .order_by(Evidence.evidence_id.asc())
        .all()
    )
    by_status = {s: 0 for s in EVIDENCE_STATUSES}
    by_verify_state = {s: 0 for s in VERIFY_STATES}
    rows = []
    broken_chains = 0
    for ev in items:
        status = ev.status or EVIDENCE_ACTIVE
        by_status[status] = by_status.get(status, 0) + 1
        if ev.verify_state:
            by_verify_state[ev.verify_state] = by_verify_state.get(ev.verify_state, 0) + 1
        chain_ok, chain_message = verify_custody_log(db, ev.evidence_id)
        if not chain_ok:
            broken_chains += 1
        entries = ev.custody_entries
        rows.append({
            "evidence_id": ev.evidence_id,
            "filename": ev.filename,
            "sha256": ev.sha256,
            "status": status,
            "verified_at": ev.verified_at.isoformat() if ev.verified_at else None,
            "verify_state": ev.verify_state,
            "custody_entries": len(entries),
            "custody_chain_valid": chain_ok,
            "custody_message": chain_message,
            "last_custody_action": entries[-1].action if entries else None,
        })
    return {
        "case_id": case_id,
        "checked_at": utc_now().isoformat(),
        "intact": by_status[EVIDENCE_QUARANTINED] == 0 and broken_chains == 0,
        "summary": {
            "total": len(items),
            "by_status": by_status,
            "by_verify_state": by_verify_state,
            "never_verified": sum(1 for ev in items if ev.verify_state is None),
            "broken_custody_chains": broken_chains,
        },
        "evidence": rows,
    }
