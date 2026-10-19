"""Role 3: SQLAlchemy database models for Pramana DFIR.

Tables:
- cases: Case metadata
- evidence: Uploaded forensic artifacts with SHA-256 and intake times
- events: Normalized parsed events adhering to contracts/event.schema.json
- findings: Intelligence claims adhering to contracts/finding.schema.json
- custody_entries: Append-only hash-chained custody log with tamper detection
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def utc_now() -> datetime:
    """Return current UTC timestamp without timezone offset issues."""
    return datetime.now(timezone.utc)


def compute_entry_hash(
    prev_hash: str,
    evidence_id: str,
    actor: str,
    action: str,
    time_iso: str,
    sha256: str,
) -> str:
    """Compute deterministic SHA-256 hash for a custody chain entry."""
    payload = f"{prev_hash}|{evidence_id}|{actor}|{action}|{time_iso}|{sha256}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class Case(Base):
    """Forensic investigation case."""

    __tablename__ = "cases"

    case_id = Column(String(64), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    evidence_items = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    events = relationship("EventModel", back_populates="case", cascade="all, delete-orphan")
    findings = relationship("FindingModel", back_populates="case", cascade="all, delete-orphan")

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "name": self.name,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Evidence(Base):
    """Forensic evidence source file."""

    __tablename__ = "evidence"

    evidence_id = Column(String(64), primary_key=True, index=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    size_bytes = Column(Integer, default=0, nullable=False)
    intake_time = Column(DateTime, default=utc_now, nullable=False)
    stored_path = Column(String(1024), nullable=True)

    case = relationship("Case", back_populates="evidence_items")
    events = relationship("EventModel", back_populates="evidence", cascade="all, delete-orphan")
    custody_entries = relationship(
        "CustodyEntry",
        back_populates="evidence",
        order_by="CustodyEntry.id",
        cascade="all, delete-orphan",
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "filename": self.filename,
            "sha256": self.sha256,
            "intake_time": (
                self.intake_time.isoformat()
                if self.intake_time
                else utc_now().isoformat()
            ),
            "custody": [entry.to_dict() for entry in self.custody_entries],
        }


class EventModel(Base):
    """Forensic event conforming to contracts/event.schema.json."""

    __tablename__ = "events"

    event_id = Column(String(64), primary_key=True, index=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False, index=True)
    evidence_id = Column(String(64), ForeignKey("evidence.evidence_id"), nullable=False, index=True)
    artifact_ref = Column(String(512), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source = Column(String(32), nullable=False, index=True)  # browser, chat, log, pcap, image
    device = Column(String(255), nullable=True)
    actor = Column(String(255), nullable=True)
    action = Column(String(128), nullable=False)
    object = Column(String(512), nullable=True)
    ip = Column(String(64), nullable=True)
    location = Column(JSON, nullable=True)  # {"lat": float, "lon": float}
    raw = Column(JSON, nullable=True)

    case = relationship("Case", back_populates="events")
    evidence = relationship("Evidence", back_populates="events")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "event_id": self.event_id,
            "case_id": self.case_id,
            "evidence_id": self.evidence_id,
            "artifact_ref": self.artifact_ref,
            "sha256": self.sha256,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source": self.source,
            "action": self.action,
        }
        if self.device is not None:
            data["device"] = self.device
        if self.actor is not None:
            data["actor"] = self.actor
        if self.object is not None:
            data["object"] = self.object
        if self.ip is not None:
            data["ip"] = self.ip
        if self.location is not None:
            data["location"] = self.location
        if self.raw is not None:
            data["raw"] = self.raw
        return data


class FindingModel(Base):
    """Intelligence finding conforming to contracts/finding.schema.json."""

    __tablename__ = "findings"

    finding_id = Column(String(64), primary_key=True, index=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False, index=True)
    type = Column(String(32), nullable=False)  # contradiction, anomaly, correlation, hypothesis
    claim = Column(Text, nullable=False)
    confidence = Column(Float, nullable=False)
    evidence_event_ids = Column(JSON, nullable=False)  # list of strings
    reasoning = Column(Text, nullable=True)
    alternatives = Column(JSON, nullable=True)  # list of {claim, confidence, needed_evidence}
    needs_human_review = Column(Boolean, default=True, nullable=False)
    status = Column(String(32), default="pending", nullable=False)  # pending, approved, rejected
    created_at = Column(DateTime, default=utc_now, nullable=False)

    case = relationship("Case", back_populates="findings")

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "finding_id": self.finding_id,
            "case_id": self.case_id,
            "type": self.type,
            "claim": self.claim,
            "confidence": self.confidence,
            "evidence_event_ids": self.evidence_event_ids or [],
            "needs_human_review": self.needs_human_review,
            "status": self.status,
        }
        if self.reasoning is not None:
            data["reasoning"] = self.reasoning
        if self.alternatives is not None:
            data["alternatives"] = self.alternatives
        return data


class CustodyEntry(Base):
    """Append-only, hash-chained custody record with cryptographic tamper detection."""

    __tablename__ = "custody_entries"

    id = Column(Integer, primary_key=True, autoincrement=True)
    evidence_id = Column(String(64), ForeignKey("evidence.evidence_id"), nullable=False, index=True)
    actor = Column(String(128), nullable=False)
    action = Column(String(128), nullable=False)
    time = Column(DateTime, default=utc_now, nullable=False)
    sha256 = Column(String(64), nullable=False)
    prev_hash = Column(String(64), nullable=False)
    entry_hash = Column(String(64), nullable=False)

    evidence = relationship("Evidence", back_populates="custody_entries")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "evidence_id": self.evidence_id,
            "actor": self.actor,
            "action": self.action,
            "time": self.time.isoformat() if self.time else None,
            "sha256": self.sha256,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }
