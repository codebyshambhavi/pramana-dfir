"""Role 3: SQLAlchemy database models for Pramana DFIR.

Tables:
- cases: Case metadata
- evidence: Uploaded forensic artifacts with SHA-256 and intake times
- events: Normalized parsed events adhering to contracts/event.schema.json
- findings: Intelligence claims adhering to contracts/finding.schema.json
- custody_entries: Append-only hash-chained custody log with tamper detection

T3 (run foundation, PRAMANA H″):
- analysis_run: write-once analysis execution with manifest and provenance hashes
- claim: content-addressed claim produced by a run
- claim_edge: lineage from a claim to events or other claims of the same run
- hypothesis_eval, source_coverage: stubs for T7 (no fields defined by H″ yet)
- schema_migrations: applied data-migration steps

Integrity rules (ORM guards at the end of this file; database triggers in db_guards):
- evidence and custody_entries rows are never deleted; evidence.sha256 never changes
- run data is write-once: no UPDATE/DELETE, and no child rows after the run row exists
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    JSON,
    String,
    Text,
    event,
    inspect,
    select,
)
from sqlalchemy.orm import Session, declarative_base, relationship

Base = declarative_base()

# Evidence lifecycle (H″). Evidence rows are never deleted; removal is a status.
EVIDENCE_ACTIVE = "ACTIVE"
EVIDENCE_QUARANTINED = "QUARANTINED"
EVIDENCE_REMOVED = "REMOVED"
EVIDENCE_STATUSES = (EVIDENCE_ACTIVE, EVIDENCE_QUARANTINED, EVIDENCE_REMOVED)

# Result of the most recent re-verification (H″ `verify_state`). NULL = never verified.
# The value set is a team decision pending contract approval (see PR notes).
VERIFY_MATCH = "MATCH"
VERIFY_MISMATCH = "MISMATCH"
VERIFY_MISSING = "MISSING"
VERIFY_CUSTODY_BROKEN = "CUSTODY_BROKEN"
VERIFY_STATES = (VERIFY_MATCH, VERIFY_MISMATCH, VERIFY_MISSING, VERIFY_CUSTODY_BROKEN)

class ImmutableRecordError(RuntimeError):
    """Raised when a write would delete evidence/custody, change an intake hash or alter run data."""


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
    # T3: lifecycle status, last verification result, and time of the last successful
    # re-hash of the stored file. `sha256` above is the intake hash and is never rewritten.
    status = Column(String(16), nullable=False, default=EVIDENCE_ACTIVE, server_default=EVIDENCE_ACTIVE)
    verified_at = Column(DateTime, nullable=True)
    verify_state = Column(String(16), nullable=True)

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
            "verify_state": self.verify_state,
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
# T3: analysis runs and their outputs (H″)
# -------------------------------------------------------------------------
#
# Write-once runs, with no lifecycle column. A run and all of its child rows are
# written in ONE transaction by app.db.runs.create_analysis_run: children first,
# the analysis_run row last. Foreign keys from children to their run are
# DEFERRABLE INITIALLY DEFERRED, so that order is legal and a missing run row
# fails the commit. After the run row exists:
#   - database triggers (app.db.db_guards) reject any child INSERT for it, and
#     any UPDATE or DELETE of run, claim, claim_edge and stub rows;
#   - the ORM guards below reject the same operations earlier, with clearer errors.
# A trigger cannot tell which transaction created a row, so the rule it enforces
# is "a child may not be inserted once its run row exists", not "only inside the
# creating transaction". See db_guards for the one residual PostgreSQL race.

CLAIM_TYPES = (
    "SAME_OBJECT_FLOW",
    "OFFHOURS_SESSION",
    "ACTOR_DEVICE_CONSISTENT",
    "LOCATION_CONFLICT",
    "NO_RECORD_IN_COVERED_WINDOW",
    "SESSION_ORIGIN_MISMATCH",
)
CLAIM_STATUSES = ("ASSERTED", "CORROBORATED", "CONTESTED", "REFUTED")
CLAIM_GRADES = ("A", "B", "C")
EDGE_REF_KINDS = ("event", "claim")
EDGE_ROLES = ("SUPPORTS", "CONTRADICTS")

_DEFERRED = {"deferrable": True, "initially": "DEFERRED"}


def _enum(name: str, values: tuple[str, ...], length: int) -> Enum:
    """Portable enum: VARCHAR + CHECK constraint on SQLite and PostgreSQL."""
    return Enum(*values, name=name, native_enum=False, create_constraint=True,
                length=length, validate_strings=True)


class AnalysisRun(Base):
    """One analysis execution (H″ fields only).

    manifest = {"evidence": [{"evidence_id", "sha256"}, ...] (ACTIVE evidence at
    creation, sorted), "assumptions": {...}}. assumptions_hash = H(assumptions).
    parser_versions is derived from the stored events of the manifest evidence.
    """

    __tablename__ = "analysis_run"

    run_id = Column(String(64), primary_key=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False, index=True)
    parent_run_id = Column(String(64), ForeignKey("analysis_run.run_id"), nullable=True, index=True)
    manifest = Column(JSON, nullable=False)
    assumptions_hash = Column(String(64), nullable=False)
    engine_version = Column(String(64), nullable=False)
    parser_versions = Column(JSON, nullable=False)
    ranking_hash = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    claims = relationship("Claim", viewonly=True, order_by="Claim.claim_id")

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "case_id": self.case_id,
            "parent_run_id": self.parent_run_id,
            "manifest": self.manifest,
            "assumptions_hash": self.assumptions_hash,
            "engine_version": self.engine_version,
            "parser_versions": self.parser_versions,
            "ranking_hash": self.ranking_hash,
            "created_at": _iso(self.created_at),
        }


class Claim(Base):
    """A content-addressed claim within a run (H″ fields).

    claim_key = H(type, canonical params)
    claim_id  = H(claim_key, sorted input event IDs, sorted input evidence SHA-256s,
                  rule_id@rule_version, assumptions_hash)
    See app.db.claims. DEVIATION from the literal H″ key: the primary key is
    (run_id, claim_id), not claim_id alone, because claim_id excludes run_id and
    the same claim legitimately recurs in later runs (pending team approval).
    """

    __tablename__ = "claim"

    run_id = Column(String(64), ForeignKey("analysis_run.run_id", **_DEFERRED), primary_key=True)
    claim_id = Column(String(64), primary_key=True)
    claim_key = Column(String(64), nullable=False, index=True)
    case_id = Column(String(64), ForeignKey("cases.case_id"), nullable=False, index=True)
    type = Column(_enum("ck_claim_type", CLAIM_TYPES, 32), nullable=False)
    params = Column(JSON, nullable=False)
    status = Column(_enum("ck_claim_status", CLAIM_STATUSES, 16), nullable=False)
    grade = Column(_enum("ck_claim_grade", CLAIM_GRADES, 1), nullable=False)
    rule_id = Column(String(128), nullable=False)
    rule_version = Column(String(64), nullable=False)
    assumptions_hash = Column(String(64), nullable=False)

    edges = relationship(
        "ClaimEdge",
        viewonly=True,
        primaryjoin="and_(Claim.run_id == foreign(ClaimEdge.run_id), Claim.claim_id == foreign(ClaimEdge.claim_id))",
        order_by="(ClaimEdge.ref_kind, ClaimEdge.ref_id, ClaimEdge.role)",
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "claim_key": self.claim_key,
            "run_id": self.run_id,
            "case_id": self.case_id,
            "type": self.type,
            "params": self.params,
            "status": self.status,
            "grade": self.grade,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "assumptions_hash": self.assumptions_hash,
        }


class ClaimEdge(Base):
    """Lineage edge from a claim to an event or another claim of the same run (H″ fields).

    DEVIATION from the literal H″ key: `run_id` is added (key: run_id, claim_id,
    ref_kind, ref_id, role) because claim_id alone no longer identifies a claim
    row (see Claim). ref_id is polymorphic (event_id or claim_id), so it has no
    foreign key; it is validated by the ORM guard and by the run-insert trigger.
    """

    __tablename__ = "claim_edge"
    __table_args__ = (
        ForeignKeyConstraint(["run_id", "claim_id"], ["claim.run_id", "claim.claim_id"], **_DEFERRED),
    )

    run_id = Column(String(64), ForeignKey("analysis_run.run_id", **_DEFERRED), primary_key=True)
    claim_id = Column(String(64), primary_key=True)
    ref_kind = Column(_enum("ck_edge_ref_kind", EDGE_REF_KINDS, 8), primary_key=True)
    ref_id = Column(String(128), primary_key=True)
    role = Column(_enum("ck_edge_role", EDGE_ROLES, 16), primary_key=True)
    weight = Column(Float, nullable=True)
    reason_code = Column(String(64), nullable=True)
    family = Column(String(64), nullable=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "claim_id": self.claim_id,
            "ref_kind": self.ref_kind,
            "ref_id": self.ref_id,
            "role": self.role,
            "weight": self.weight,
            "reason_code": self.reason_code,
            "family": self.family,
        }


class HypothesisEval(Base):
    """STUB. Hypothesis evaluation results of a run (T7).

    H″ requires evaluation and ranking with required/expected/forbidden items and
    coverage-aware MISSING vs UNOBSERVABLE, but defines no persistence fields.
    Only the run link exists; columns are added additively once the schema is agreed.
    """

    __tablename__ = "hypothesis_eval"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(64), ForeignKey("analysis_run.run_id", **_DEFERRED), nullable=False, index=True)


class SourceCoverage(Base):
    """STUB. Source / witness-family coverage of a run (T7).

    H″ requires coverage-aware MISSING vs UNOBSERVABLE and witness families, but
    defines no persistence fields. Only the run link exists for now.
    """

    __tablename__ = "source_coverage"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(64), ForeignKey("analysis_run.run_id", **_DEFERRED), nullable=False, index=True)


class SchemaMigration(Base):
    """Data migration steps already applied (infrastructure, see app.db.migrate)."""

    __tablename__ = "schema_migrations"

    version = Column(String(64), primary_key=True)
    applied_at = Column(DateTime, default=utc_now, nullable=False)


# -------------------------------------------------------------------------
# ORM-level integrity guards. Database-level equivalents: app.db.db_guards.
# -------------------------------------------------------------------------

RUN_TABLE_MODELS = (AnalysisRun, Claim, ClaimEdge, HypothesisEval, SourceCoverage)
RUN_CHILD_MODELS = (Claim, ClaimEdge, HypothesisEval, SourceCoverage)


def _run_row_exists(session: Session, run_id: str | None) -> bool:
    """True if the run row is already in the database (or flushed in this transaction)."""
    if run_id is None:
        return False
    for obj in session.new:
        if isinstance(obj, AnalysisRun) and obj.run_id == run_id:
            return False  # pending in this flush; the run row goes in after its children
    with session.no_autoflush:
        return session.execute(select(AnalysisRun.run_id).where(AnalysisRun.run_id == run_id)).first() is not None


@event.listens_for(Session, "before_flush")
def _enforce_integrity(session: Session, flush_context, instances) -> None:
    for obj in session.deleted:
        if isinstance(obj, (Evidence, CustodyEntry)):
            raise ImmutableRecordError(
                f"{type(obj).__name__} rows are never deleted; change evidence status instead"
            )
        if isinstance(obj, RUN_TABLE_MODELS):
            raise ImmutableRecordError(f"{type(obj).__tablename__} rows are immutable and never deleted")

    for obj in session.dirty:
        if not session.is_modified(obj, include_collections=False):
            continue
        if isinstance(obj, Evidence) and inspect(obj).attrs.sha256.history.deleted:
            raise ImmutableRecordError("evidence.sha256 is the intake hash and cannot be changed")
        if isinstance(obj, RUN_TABLE_MODELS):
            raise ImmutableRecordError(f"{type(obj).__tablename__} rows are write-once")

    for obj in session.new:
        if isinstance(obj, RUN_CHILD_MODELS) and _run_row_exists(session, obj.run_id):
            raise ImmutableRecordError(
                f"run {obj.run_id} already exists; records can only be written with the run itself"
            )


@event.listens_for(Session, "do_orm_execute")
def _block_bulk_writes(state) -> None:
    """Bulk ORM UPDATE/DELETE skips before_flush, so it is checked here."""
    if not (state.is_update or state.is_delete):
        return
    for mapper in state.all_mappers:
        cls = mapper.class_
        if cls is Evidence:
            raise ImmutableRecordError(
                "bulk UPDATE/DELETE of evidence is not allowed; use the evidence services, which write custody"
            )
        if cls is CustodyEntry and state.is_delete:
            raise ImmutableRecordError("custody_entries rows are never deleted")
        if cls in RUN_TABLE_MODELS:
            raise ImmutableRecordError(f"{cls.__tablename__} rows are write-once")
