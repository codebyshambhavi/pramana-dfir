"""Role 3: SQLAlchemy database models for Pramana DFIR.

Tables:
- cases: Case metadata
- evidence: Uploaded forensic artifacts with SHA-256 and intake times
- events: Normalized parsed events adhering to contracts/event.schema.json
- findings: Intelligence claims adhering to contracts/finding.schema.json
- custody_entries: Append-only hash-chained custody log with tamper detection

T3 (run foundation):
- analysis_run: One analysis execution with a frozen snapshot of its evidence inputs
- claim: A statement produced by a run, linked to supporting events and evidence
- claim_edge: Directed relation between two claims of the same run
- hypothesis_eval: Evaluation of one hypothesis claim within a run
- source_coverage: Per-evidence/source coverage of a run's inputs

Integrity rules enforced at flush time (see the guards at the end of this file):
- evidence and custody_entries rows are never deleted
- a finalized analysis_run (COMPLETED or FAILED) and its child rows are immutable
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
    event,
    inspect,
)
from sqlalchemy.orm import Session, declarative_base, relationship

Base = declarative_base()

# Evidence lifecycle. Evidence rows are never deleted; removal is a status.
EVIDENCE_ACTIVE = "ACTIVE"
EVIDENCE_VERIFIED = "VERIFIED"
EVIDENCE_QUARANTINED = "QUARANTINED"
EVIDENCE_REMOVED = "REMOVED"
EVIDENCE_STATUSES = (EVIDENCE_ACTIVE, EVIDENCE_VERIFIED, EVIDENCE_QUARANTINED, EVIDENCE_REMOVED)

# Analysis run lifecycle. Only RUNNING runs may change.
RUN_RUNNING = "RUNNING"
RUN_COMPLETED = "COMPLETED"
RUN_FAILED = "FAILED"
RUN_STATUSES = (RUN_RUNNING, RUN_COMPLETED, RUN_FAILED)
RUN_FINAL_STATUSES = (RUN_COMPLETED, RUN_FAILED)


class ImmutableRecordError(RuntimeError):
    """Raised when a flush would delete evidence/custody or change a finalized run."""


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


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

    # No delete cascade: evidence rows must outlive any ORM delete attempt.
    evidence_items = relationship("Evidence", back_populates="case", cascade="save-update, merge")
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
    # T3: lifecycle status and time of the last successful re-hash of the stored file.
    # `sha256` above is the intake hash and is never rewritten.
    status = Column(String(16), nullable=False, default=EVIDENCE_ACTIVE, server_default=EVIDENCE_ACTIVE)
    verified_at = Column(DateTime, nullable=True)

    case = relationship("Case", back_populates="evidence_items")
    events = relationship("EventModel", back_populates="evidence", cascade="all, delete-orphan")
    # No delete cascade: the custody chain is append-only.
    custody_entries = relationship(
        "CustodyEntry",
        back_populates="evidence",
        order_by="CustodyEntry.id",
        cascade="save-update, merge",
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
            "status": self.status or EVIDENCE_ACTIVE,
            "verified_at": _iso(self.verified_at),
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
    # T3: Event v1.1 provenance fields (optional in contracts/event.schema.json).
    parser_version = Column(String(64), nullable=True)
    tz_assumption = Column(String(32), nullable=True)
    family = Column(String(64), nullable=True)

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
        if self.parser_version is not None:
            data["parser_version"] = self.parser_version
        if self.tz_assumption is not None:
            data["tz_assumption"] = self.tz_assumption
        if self.family is not None:
            data["family"] = self.family
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


# -------------------------------------------------------------------------
# T3: analysis runs and their outputs
# -------------------------------------------------------------------------


class AnalysisRun(Base):
    """One analysis execution over a case.

    `evidence_snapshot` freezes the inputs at creation time as a list of
    {evidence_id, sha256, status, included}. `input_digest` is the SHA-256 of
    that snapshot in canonical JSON. Later evidence state changes (for example
    quarantine) never touch an existing run. Once the run is COMPLETED or FAILED,
    the run and all of its child rows are immutable.
    """

    __tablename__ = "analysis_run"

    run_id = Column(String(64), primary_key=True, index=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False, index=True)
    status = Column(String(16), nullable=False, default=RUN_RUNNING, server_default=RUN_RUNNING)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    engine_version = Column(String(64), nullable=True)
    config = Column(JSON, nullable=True)
    evidence_snapshot = Column(JSON, nullable=False)
    input_digest = Column(String(64), nullable=False)
    error = Column(Text, nullable=True)

    claims = relationship("Claim", back_populates="run", order_by="Claim.claim_id")
    claim_edges = relationship("ClaimEdge", back_populates="run", order_by="ClaimEdge.id")
    hypothesis_evals = relationship("HypothesisEval", back_populates="run", order_by="HypothesisEval.id")
    source_coverage = relationship("SourceCoverage", back_populates="run", order_by="SourceCoverage.id")

    @property
    def is_final(self) -> bool:
        return self.status in RUN_FINAL_STATUSES

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "case_id": self.case_id,
            "status": self.status,
            "created_at": _iso(self.created_at),
            "completed_at": _iso(self.completed_at),
            "engine_version": self.engine_version,
            "config": self.config,
            "evidence_snapshot": self.evidence_snapshot or [],
            "input_digest": self.input_digest,
            "error": self.error,
        }


class Claim(Base):
    """A statement produced by a run, grounded in events and evidence."""

    __tablename__ = "claim"

    claim_id = Column(String(64), primary_key=True, index=True)
    run_id = Column(String(64), ForeignKey("analysis_run.run_id"), nullable=False, index=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False, index=True)
    kind = Column(String(32), nullable=False)  # e.g. observation, anomaly, correlation, contradiction, hypothesis
    statement = Column(Text, nullable=False)
    confidence = Column(Float, nullable=True)
    event_ids = Column(JSON, nullable=False, default=list)
    evidence_ids = Column(JSON, nullable=False, default=list)
    rule_id = Column(String(128), nullable=True)
    details = Column(JSON, nullable=True)
    needs_human_review = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    run = relationship("AnalysisRun", back_populates="claims")

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "kind": self.kind,
            "statement": self.statement,
            "confidence": self.confidence,
            "event_ids": self.event_ids or [],
            "evidence_ids": self.evidence_ids or [],
            "rule_id": self.rule_id,
            "details": self.details,
            "needs_human_review": self.needs_human_review,
            "created_at": _iso(self.created_at),
        }


class ClaimEdge(Base):
    """Directed relation between two claims of the same run (supports, contradicts, derives_from, ...)."""

    __tablename__ = "claim_edge"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(64), ForeignKey("analysis_run.run_id"), nullable=False, index=True)
    src_claim_id = Column(String(64), ForeignKey("claim.claim_id"), nullable=False, index=True)
    dst_claim_id = Column(String(64), ForeignKey("claim.claim_id"), nullable=False, index=True)
    relation = Column(String(32), nullable=False)
    weight = Column(Float, nullable=True)
    details = Column(JSON, nullable=True)

    run = relationship("AnalysisRun", back_populates="claim_edges")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "run_id": self.run_id,
            "src_claim_id": self.src_claim_id,
            "dst_claim_id": self.dst_claim_id,
            "relation": self.relation,
            "weight": self.weight,
            "details": self.details,
        }


class HypothesisEval(Base):
    """Evaluation of one hypothesis claim within a run."""

    __tablename__ = "hypothesis_eval"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(64), ForeignKey("analysis_run.run_id"), nullable=False, index=True)
    hypothesis_claim_id = Column(String(64), ForeignKey("claim.claim_id"), nullable=False, index=True)
    verdict = Column(String(32), nullable=True)  # e.g. supported, refuted, inconclusive
    score = Column(Float, nullable=True)
    supporting_claim_ids = Column(JSON, nullable=False, default=list)
    contradicting_claim_ids = Column(JSON, nullable=False, default=list)
    missing_evidence = Column(JSON, nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    run = relationship("AnalysisRun", back_populates="hypothesis_evals")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "run_id": self.run_id,
            "hypothesis_claim_id": self.hypothesis_claim_id,
            "verdict": self.verdict,
            "score": self.score,
            "supporting_claim_ids": self.supporting_claim_ids or [],
            "contradicting_claim_ids": self.contradicting_claim_ids or [],
            "missing_evidence": self.missing_evidence,
            "details": self.details,
            "created_at": _iso(self.created_at),
        }


class SourceCoverage(Base):
    """What one evidence item / source / artifact family contributed to a run."""

    __tablename__ = "source_coverage"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(64), ForeignKey("analysis_run.run_id"), nullable=False, index=True)
    evidence_id = Column(String(64), ForeignKey("evidence.evidence_id"), nullable=False, index=True)
    source = Column(String(32), nullable=True)
    family = Column(String(64), nullable=True)
    included = Column(Boolean, nullable=False, default=True)
    reason = Column(Text, nullable=True)  # why excluded, e.g. "evidence QUARANTINED"
    event_count = Column(Integer, nullable=False, default=0)
    time_start = Column(DateTime, nullable=True)
    time_end = Column(DateTime, nullable=True)
    details = Column(JSON, nullable=True)

    run = relationship("AnalysisRun", back_populates="source_coverage")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "run_id": self.run_id,
            "evidence_id": self.evidence_id,
            "source": self.source,
            "family": self.family,
            "included": self.included,
            "reason": self.reason,
            "event_count": self.event_count,
            "time_start": _iso(self.time_start),
            "time_end": _iso(self.time_end),
            "details": self.details,
        }


# -------------------------------------------------------------------------
# Flush-time integrity guards
# -------------------------------------------------------------------------

_RUN_CHILD_MODELS = (Claim, ClaimEdge, HypothesisEval, SourceCoverage)


def _committed_status(run: AnalysisRun) -> str | None:
    """Status as last loaded from / written to the database (ignores pending edits)."""
    history = inspect(run).attrs.status.history
    if history.deleted:
        return history.deleted[0]
    if history.unchanged:
        return history.unchanged[0]
    return run.status


def _run_is_final(session: Session, run_id: str | None) -> bool:
    if run_id is None:
        return False
    for obj in session.new:
        if isinstance(obj, AnalysisRun) and obj.run_id == run_id:
            return False  # created in this flush, so not yet finalized in the database
    with session.no_autoflush:
        run = session.get(AnalysisRun, run_id)
    return run is not None and _committed_status(run) in RUN_FINAL_STATUSES


@event.listens_for(Session, "before_flush")
def _enforce_integrity(session: Session, flush_context, instances) -> None:
    for obj in session.deleted:
        if isinstance(obj, (Evidence, CustodyEntry)):
            raise ImmutableRecordError(
                f"{type(obj).__name__} rows are never deleted; change evidence status instead"
            )
        if isinstance(obj, AnalysisRun):
            raise ImmutableRecordError("analysis_run rows are never deleted")
        if isinstance(obj, _RUN_CHILD_MODELS) and _run_is_final(session, obj.run_id):
            raise ImmutableRecordError(f"run {obj.run_id} is finalized; its records cannot be deleted")

    for obj in session.dirty:
        if not session.is_modified(obj, include_collections=False):
            continue
        if isinstance(obj, Evidence) and inspect(obj).attrs.sha256.history.deleted:
            raise ImmutableRecordError("evidence.sha256 is the intake hash and cannot be changed")
        if isinstance(obj, AnalysisRun) and _committed_status(obj) in RUN_FINAL_STATUSES:
            raise ImmutableRecordError(f"run {obj.run_id} is finalized and immutable")
        if isinstance(obj, _RUN_CHILD_MODELS) and _run_is_final(session, obj.run_id):
            raise ImmutableRecordError(f"run {obj.run_id} is finalized; its records cannot change")

    for obj in session.new:
        if isinstance(obj, _RUN_CHILD_MODELS) and _run_is_final(session, obj.run_id):
            raise ImmutableRecordError(f"run {obj.run_id} is finalized; no records can be added")
