"""Shared helpers for Role 2 (Intelligence).

Foundation only: no correlation, anomaly, contradiction, hypothesis,
authenticity or LLM logic lives here.

Timestamp policy
----------------
Every timestamp is normalized to a **UTC-naive** ``datetime`` (no tzinfo, value
expressed in UTC) so all comparisons are consistent.

* Timezone-aware input (``...Z`` or ``...+05:30``) is converted to UTC.
* Naive input (no ``Z``/offset) is **assumed to already be UTC**. It is NOT
  assumed to be IST or any local time: the backend may serialize UTC datetimes
  without a suffix, and guessing a local zone would silently shift events.
  If a source is later found to emit local naive times, fix it at the source
  (Role 1), not here.

Finding IDs
-----------
``F-`` + first 16 hex chars of SHA-256 over canonical JSON of
``[case_id, finding_type, rule_id, sorted unique event ids]``. Deterministic,
case-scoped, never random.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator

CONTRACTS_DIR = Path(__file__).resolve().parent.parent / "contracts"
FINDING_SCHEMA_PATH = CONTRACTS_DIR / "finding.schema.json"

FINDING_STATUS_PENDING = "pending"


# --- exceptions -------------------------------------------------------------
class IntelligenceError(Exception):
    """Base class for Role 2 errors."""


class EventError(IntelligenceError, ValueError):
    """An input Event is unusable (missing event_id/timestamp, wrong type)."""


class InvalidTimestampError(EventError):
    """A timestamp could not be parsed as ISO 8601."""


class FindingValidationError(IntelligenceError, ValueError):
    """A Finding does not match contracts/finding.schema.json."""


class UnknownEventIdError(IntelligenceError, ValueError):
    """A Finding cites Event IDs that were not supplied to Role 2."""


# --- timestamps -------------------------------------------------------------
def parse_timestamp(value: Any) -> datetime:
    """Parse an ISO 8601 string into a UTC-naive ``datetime``.

    Aware values are converted to UTC; naive values are taken as UTC (see the
    module docstring). Raises ``InvalidTimestampError`` for anything else.
    """
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise InvalidTimestampError("Empty timestamp")
        if text[-1] in "zZ":  # explicit, independent of fromisoformat's Z support
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise InvalidTimestampError(f"Invalid ISO 8601 timestamp: {value!r}") from exc
    else:
        raise InvalidTimestampError(f"Timestamp must be a string, got {type(value).__name__}")

    if dt.tzinfo is not None and dt.utcoffset() is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.replace(tzinfo=None)


# --- events -----------------------------------------------------------------
@dataclass(frozen=True)
class NormalizedEvent:
    """Read-only, parsed view of an Event dictionary.

    Fields mirror contracts/event.schema.json. Absent optional fields are
    ``None``. ``raw`` is a deep copy; its contents are never interpreted.
    ``location`` is a ``(lat, lon)`` tuple or ``None``.
    """

    event_id: str
    timestamp: datetime  # UTC-naive
    case_id: str | None = None
    evidence_id: str | None = None
    artifact_ref: str | None = None
    sha256: str | None = None  # hash of the SOURCE FILE, not of this event
    source: str | None = None
    action: str | None = None
    device: str | None = None
    actor: str | None = None
    object: str | None = None
    ip: str | None = None
    location: tuple[float, float] | None = None
    raw: dict[str, Any] = field(default_factory=dict)


def _location(value: Any) -> tuple[float, float] | None:
    if not isinstance(value, Mapping):
        return None
    lat, lon = value.get("lat"), value.get("lon")
    if isinstance(lat, bool) or isinstance(lon, bool):
        return None
    if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
        return float(lat), float(lon)
    return None


def get_event_id(event: Mapping[str, Any]) -> str:
    """Return the event's ID as an opaque string (never parsed or ordered numerically)."""
    if not isinstance(event, Mapping):
        raise EventError(f"Event must be a dict, got {type(event).__name__}")
    value = event.get("event_id")
    if not isinstance(value, str) or value == "":
        raise EventError("Event is missing a non-empty string 'event_id'")
    return value


def extract_event_ids(events: Iterable[Mapping[str, Any]]) -> list[str]:
    """Event IDs in input order (duplicates preserved)."""
    return [get_event_id(e) for e in events]


def event_id_set(events: Iterable[Mapping[str, Any]]) -> frozenset[str]:
    """The set of Event IDs supplied to Role 2."""
    return frozenset(extract_event_ids(events))


def normalize_event(event: Mapping[str, Any]) -> NormalizedEvent:
    """Build a ``NormalizedEvent`` from an Event dict without mutating it."""
    event_id = get_event_id(event)
    if "timestamp" not in event:
        raise EventError(f"Event {event_id!r} is missing 'timestamp'")
    try:
        ts = parse_timestamp(event["timestamp"])
    except InvalidTimestampError as exc:
        raise InvalidTimestampError(f"Event {event_id!r}: {exc}") from exc
    raw = event.get("raw")
    return NormalizedEvent(
        event_id=event_id,
        timestamp=ts,
        case_id=event.get("case_id"),
        evidence_id=event.get("evidence_id"),
        artifact_ref=event.get("artifact_ref"),
        sha256=event.get("sha256"),
        source=event.get("source"),
        action=event.get("action"),
        device=event.get("device"),
        actor=event.get("actor"),
        object=event.get("object"),
        ip=event.get("ip"),
        location=_location(event.get("location")),
        raw=copy.deepcopy(raw) if isinstance(raw, dict) else {},
    )


def sort_events(events: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Return a new list of the same event dicts, oldest first.

    Ties on timestamp are broken by ``event_id`` (plain string comparison), so
    the order never depends on input or database order. Inputs are not mutated.
    """
    return sorted(events, key=lambda e: (normalize_event(e).timestamp, get_event_id(e)))


def normalize_events(events: Iterable[Mapping[str, Any]]) -> list[NormalizedEvent]:
    """Normalize and chronologically sort events (same ordering as ``sort_events``)."""
    return sorted(
        (normalize_event(e) for e in events), key=lambda n: (n.timestamp, n.event_id)
    )


# --- finding IDs ------------------------------------------------------------
def make_finding_id(
    case_id: str, finding_type: str, rule_id: str, event_ids: Iterable[str]
) -> str:
    """Deterministic, case-scoped Finding ID: ``F-<16 hex>``."""
    payload = json.dumps(
        [case_id, finding_type, rule_id, sorted(set(event_ids))],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return "F-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


# --- finding validation -----------------------------------------------------
@lru_cache(maxsize=1)
def _finding_validator() -> Draft202012Validator:
    with FINDING_SCHEMA_PATH.open(encoding="utf-8") as fh:
        schema = json.load(fh)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate_finding(finding: Any) -> None:
    """Validate against the real contracts/finding.schema.json.

    Raises ``FindingValidationError`` on any violation. Also rejects NaN/inf
    confidence values, which a plain min/max schema check lets through.
    """
    errors = sorted(_finding_validator().iter_errors(finding), key=lambda e: list(e.path))
    if errors:
        details = "; ".join(
            f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors
        )
        raise FindingValidationError(f"Finding violates finding.schema.json: {details}")
    confidences = [finding["confidence"]] + [
        a["confidence"] for a in finding.get("alternatives", [])
    ]
    if not all(math.isfinite(c) for c in confidences):
        raise FindingValidationError("Finding confidence must be a finite number")


def check_event_ids_known(finding: Mapping[str, Any], known_event_ids: Iterable[str]) -> None:
    """Raise ``UnknownEventIdError`` if the finding cites any ID not in ``known_event_ids``.

    Never filters or repairs: a bad citation is an error, not something to hide.
    """
    known = known_event_ids if isinstance(known_event_ids, (set, frozenset)) else set(known_event_ids)
    cited = finding.get("evidence_event_ids", [])
    unknown = sorted({i for i in cited if i not in known})
    if unknown:
        raise UnknownEventIdError(
            f"Finding {finding.get('finding_id')!r} cites unknown event IDs: {unknown}"
        )


# --- finding builder --------------------------------------------------------
def make_finding(
    *,
    case_id: str,
    finding_type: str,
    rule_id: str,
    claim: str,
    confidence: float,
    evidence_event_ids: Iterable[str],
    reasoning: str,
    known_event_ids: Iterable[str],
    needs_human_review: bool = True,
    alternatives: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a schema-valid Finding with ``status="pending"``.

    ``rule_id`` feeds only the deterministic finding_id; it is not an output
    field. ``known_event_ids`` (the IDs supplied to Role 2) is required so a
    Finding can never cite an Event that does not exist. Cited IDs are stored
    de-duplicated and sorted. Raises ``UnknownEventIdError`` or
    ``FindingValidationError`` instead of repairing anything.
    """
    cited = sorted(set(evidence_event_ids))
    finding: dict[str, Any] = {
        "finding_id": make_finding_id(case_id, finding_type, rule_id, cited),
        "case_id": case_id,
        "type": finding_type,
        "claim": claim,
        "confidence": confidence,
        "evidence_event_ids": cited,
        "reasoning": reasoning,
        "needs_human_review": needs_human_review,
        "status": FINDING_STATUS_PENDING,
    }
    if alternatives is not None:
        finding["alternatives"] = copy.deepcopy(alternatives)
    validate_finding(finding)
    check_event_ids_known(finding, known_event_ids)
    return finding
