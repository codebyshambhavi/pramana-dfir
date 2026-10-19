"""Role 3: Database engine, session management, and custody service."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.db.models import Base, CustodyEntry, compute_entry_hash, utc_now

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./pramana.db")

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db(target_engine=None) -> None:
    """Initialize all tables."""
    eng = target_engine or engine
    Base.metadata.create_all(bind=eng)


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
    db.commit()
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
