"""Role 3 / T3: content-addressed claims and lineage (PRAMANA H″).

    claim_key = H(type, canonical params)
    claim_id  = H(claim_key, sorted input event IDs, sorted input evidence SHA-256s,
                  rule_id@rule_version, assumptions_hash)

H is SHA-256 (hex) over canonical JSON: keys sorted, no insignificant whitespace,
UTF-8, NaN/Infinity rejected. Each H call hashes one JSON array of its arguments.

Input events of a claim are the events it references with role SUPPORTS. Events it
references with role CONTRADICTS are lineage, not identity, so the same claim keeps
its ID when later evidence contests it. Input evidence SHA-256s are the intake
hashes of the evidence those input events came from.

The canonical-JSON choice and the SUPPORTS-only input rule are interpretations of
H″ pending team approval (see PR notes).
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Sequence

from sqlalchemy.orm import Session

from app.db.models import (
    CLAIM_GRADES,
    CLAIM_STATUSES,
    CLAIM_TYPES,
    EDGE_REF_KINDS,
    EDGE_ROLES,
    Claim,
    ClaimEdge,
    EventModel,
    Evidence,
)


class ClaimValidationError(ValueError):
    """A claim or edge violates the H″ schema, the enums or same-run lineage rules."""


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def H(*parts: Any) -> str:
    """SHA-256 hex of the canonical JSON array of `parts`."""
    return hashlib.sha256(canonical_json(list(parts)).encode("utf-8")).hexdigest()


def compute_claim_key(claim_type: str, params: dict[str, Any]) -> str:
    return H(claim_type, params)


def compute_claim_id(
    claim_key: str,
    input_event_ids: Sequence[str],
    input_evidence_sha256s: Sequence[str],
    rule_id: str,
    rule_version: str,
    assumptions_hash: str,
) -> str:
    return H(
        claim_key,
        sorted(set(input_event_ids)),
        sorted(set(input_evidence_sha256s)),
        f"{rule_id}@{rule_version}",
        assumptions_hash,
    )


@dataclass
class EdgeSpec:
    """One lineage edge. For ref_kind="claim", ref_id may be a claim_id or the
    `label` of another ClaimSpec in the same run."""

    ref_kind: str
    ref_id: str
    role: str
    weight: float | None = None
    reason_code: str | None = None
    family: str | None = None


@dataclass
class ClaimSpec:
    type: str
    params: dict[str, Any]
    status: str
    grade: str
    rule_id: str
    rule_version: str
    edges: list[EdgeSpec] = field(default_factory=list)
    label: str | None = None  # local reference for claim->claim edges; not stored


def _check_enum(value: str, allowed: tuple[str, ...], what: str) -> None:
    if value not in allowed:
        raise ClaimValidationError(f"{what} {value!r} is not one of {', '.join(allowed)}")


def build_claim_rows(
    db: Session,
    *,
    run_id: str,
    case_id: str,
    assumptions_hash: str,
    manifest_evidence: list[dict[str, str]],
    specs: Sequence[ClaimSpec],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Validate claim specs and return (claim rows, edge rows) ready to insert.

    Enforces: G7 enums; event edges point to events of this case whose evidence is
    in the run manifest (so quarantined/removed evidence is never silently used);
    claim edges point to claims of this same run; no duplicate claims or edges.
    """
    manifest_sha = {item["evidence_id"]: item["sha256"] for item in manifest_evidence}

    event_ids = {e.ref_id for s in specs for e in s.edges if e.ref_kind == "event"}
    events: dict[str, EventModel] = {}
    if event_ids:
        for ev in db.query(EventModel).filter(EventModel.event_id.in_(event_ids)).all():
            events[ev.event_id] = ev

    claim_rows: list[dict[str, Any]] = []
    ids_by_label: dict[str, str] = {}
    for spec in specs:
        _check_enum(spec.type, CLAIM_TYPES, "claim type")
        _check_enum(spec.status, CLAIM_STATUSES, "claim status")
        _check_enum(spec.grade, CLAIM_GRADES, "claim grade")
        if not isinstance(spec.params, dict):
            raise ClaimValidationError("claim params must be a JSON object")
        if not spec.rule_id or not spec.rule_version:
            raise ClaimValidationError("rule_id and rule_version are required")

        has_support = any(edge.role == "SUPPORTS" for edge in spec.edges)
        if not has_support and spec.status != "ASSUMED":
            raise ClaimValidationError(
                f"Claim {spec.type} must be backed by at least one ClaimEdge with role 'SUPPORTS' "
                f"unless explicitly marked ASSUMED (status was {spec.status!r})"
            )

        input_events: list[str] = []
        for edge in spec.edges:
            _check_enum(edge.ref_kind, EDGE_REF_KINDS, "edge ref_kind")
            _check_enum(edge.role, EDGE_ROLES, "edge role")
            if edge.ref_kind != "event":
                continue
            ev = events.get(edge.ref_id)
            if ev is None:
                raise ClaimValidationError(f"event {edge.ref_id!r} does not exist")
            if ev.case_id != case_id:
                raise ClaimValidationError(f"event {edge.ref_id!r} belongs to case {ev.case_id}, not {case_id}")
            if ev.evidence_id not in manifest_sha:
                raise ClaimValidationError(
                    f"event {edge.ref_id!r} comes from evidence {ev.evidence_id}, which is not ACTIVE "
                    "in this run's manifest"
                )
            if edge.role == "SUPPORTS":
                input_events.append(edge.ref_id)
        input_shas = [manifest_sha[events[e].evidence_id] for e in input_events]
        for sha in input_shas:
            if not _HEX64.match(sha or ""):
                raise ClaimValidationError(f"evidence intake SHA-256 {sha!r} is invalid")
        claim_key = compute_claim_key(spec.type, spec.params)
        claim_id = compute_claim_id(claim_key, input_events, input_shas, spec.rule_id, spec.rule_version,
                                    assumptions_hash)
        if any(row["claim_id"] == claim_id for row in claim_rows):
            raise ClaimValidationError(f"duplicate claim {claim_id} in run (identical type, params and inputs)")
        if spec.label:
            if spec.label in ids_by_label:
                raise ClaimValidationError(f"duplicate claim label {spec.label!r}")
            ids_by_label[spec.label] = claim_id
        claim_rows.append({
            "run_id": run_id,
            "claim_id": claim_id,
            "claim_key": claim_key,
            "case_id": case_id,
            "type": spec.type,
            "params": spec.params,
            "status": spec.status,
            "grade": spec.grade,
            "rule_id": spec.rule_id,
            "rule_version": spec.rule_version,
            "assumptions_hash": assumptions_hash,
        })

    run_claim_ids = {row["claim_id"] for row in claim_rows}
    edge_rows: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str, str, str]] = set()
    for spec, row in zip(specs, claim_rows):
        for edge in spec.edges:
            ref_id = edge.ref_id
            if edge.ref_kind == "claim":
                ref_id = ids_by_label.get(ref_id, ref_id)
                if ref_id not in run_claim_ids:
                    raise ClaimValidationError(f"claim edge target {edge.ref_id!r} is not a claim of this run")
            key = (row["claim_id"], edge.ref_kind, ref_id, edge.role)
            if key in seen_edges:
                raise ClaimValidationError(f"duplicate edge {key}")
            seen_edges.add(key)
            edge_rows.append({
                "run_id": run_id,
                "claim_id": row["claim_id"],
                "ref_kind": edge.ref_kind,
                "ref_id": ref_id,
                "role": edge.role,
                "weight": edge.weight,
                "reason_code": edge.reason_code,
                "family": edge.family,
            })
    return claim_rows, edge_rows


def _get_claim(db: Session, run_id: str, claim_id: str) -> Claim:
    claim = db.get(Claim, (run_id, claim_id))
    if claim is None:
        raise LookupError(f"Claim {claim_id} not found in run {run_id}")
    return claim


def recompute_claim_id(db: Session, run_id: str, claim_id: str) -> str:
    """Recompute a stored claim's ID from its row, its SUPPORTS event edges and their evidence hashes."""
    claim = _get_claim(db, run_id, claim_id)
    input_events = [e.ref_id for e in claim.edges if e.ref_kind == "event" and e.role == "SUPPORTS"]
    shas: list[str] = []
    for event_id in input_events:
        ev = db.get(EventModel, event_id)
        if ev is None:
            raise LookupError(f"event {event_id} referenced by claim {claim_id} no longer exists")
        shas.append(db.get(Evidence, ev.evidence_id).sha256)
    claim_key = compute_claim_key(claim.type, claim.params)
    if claim_key != claim.claim_key:
        return ""
    return compute_claim_id(claim_key, input_events, shas, claim.rule_id, claim.rule_version, claim.assumptions_hash)


def verify_claim_id(db: Session, run_id: str, claim_id: str) -> bool:
    return recompute_claim_id(db, run_id, claim_id) == claim_id


def claim_lineage(db: Session, run_id: str, claim_id: str, _seen: set[str] | None = None) -> dict[str, Any]:
    """Claim -> edges -> events -> evidence intake SHA-256, recursing through claim edges of the same run."""
    seen = _seen if _seen is not None else set()
    claim = _get_claim(db, run_id, claim_id)
    seen.add(claim_id)
    events, claims = [], []
    for edge in claim.edges:
        if edge.ref_kind == "event":
            ev = db.get(EventModel, edge.ref_id)
            evidence = db.get(Evidence, ev.evidence_id) if ev else None
            events.append({
                "event_id": edge.ref_id,
                "role": edge.role,
                "family": edge.family,
                "artifact_ref": ev.artifact_ref if ev else None,
                "evidence_id": ev.evidence_id if ev else None,
                "evidence_sha256": evidence.sha256 if evidence else None,
            })
        elif edge.ref_id in seen:
            claims.append({"claim_id": edge.ref_id, "role": edge.role, "cycle": True})
        else:
            claims.append({"claim_id": edge.ref_id, "role": edge.role,
                           "lineage": claim_lineage(db, run_id, edge.ref_id, seen)})
    return {"claim": claim.to_dict(), "events": events, "claims": claims}
