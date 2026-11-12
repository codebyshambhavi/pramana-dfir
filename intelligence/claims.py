"""Role 3 / T6: Rule-driven claim-generation and lifecycle engine.

Converts T5 correlation results and intelligence findings into content-addressed,
evidence-grounded claims with complete event and claim lineage.

Supported Claim Types (PRAMANA H″):
1. SAME_OBJECT_FLOW: Promoted cross-source relationships tracing object movements.
2. OFFHOURS_SESSION: Anomaly claims for login/session activity during odd hours.
3. ACTOR_DEVICE_CONSISTENT: Multi-source corroboration of consistent actor-device bindings.
4. LOCATION_CONFLICT: Cross-source contradiction where travel speed is physically impossible.
5. NO_RECORD_IN_COVERED_WINDOW: Certified absence of expected records in a covered window.
6. SESSION_ORIGIN_MISMATCH: Contradictory network origin / IP reporting for a session.

Two-level witness-family independence:
    family = (source kind, device)
Multiple events from the same family count ONCE toward independence.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from .anomalies import find_anomalies, _odd_status
from .contradictions import find_contradictions
from .correlate import CandidateRelationship, generate_candidates
from .entities import normalize_actor, normalize_device, normalize_file_object
from .config import get_timezone
from .timeline import SourceClock, event_interval, load_source_clocks, to_case_time, tz_label

# Import or define ClaimSpec and EdgeSpec compatible with app.db.claims
try:
    from app.db.claims import ClaimSpec, EdgeSpec
except ImportError:
    @dataclass
    class EdgeSpec:
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
        label: str | None = None


# Supported Enums (aligned with models.py and H″)
CLAIM_TYPES = (
    "SAME_OBJECT_FLOW",
    "OFFHOURS_SESSION",
    "ACTOR_DEVICE_CONSISTENT",
    "LOCATION_CONFLICT",
    "NO_RECORD_IN_COVERED_WINDOW",
    "SESSION_ORIGIN_MISMATCH",
)
CLAIM_STATUSES = ("ASSERTED", "CORROBORATED", "CONTESTED", "REFUTED", "ASSUMED")
CLAIM_GRADES = ("A", "B", "C")
EDGE_ROLES = ("SUPPORTS", "CONTRADICTS")
_PLACEHOLDER_IDENTIFIERS = frozenset({"unknown", "none", "null", "n/a"})
_CRYPTOGRAPHIC_HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_SHORT_HEX_IDENTIFIER_PATTERN = re.compile(r"^[0-9a-fA-F]{1,31}$")


def _valid_shared_object(value: Any) -> str | None:
    """Return an exact object identifier safe for SAME_OBJECT_FLOW.

    Promoted links normally contain values from ``normalize_file_object``, but
    claims are also generated from persisted/imported link records.  Reject
    placeholders and short hexadecimal values here as a second provenance
    boundary so they cannot become object-flow evidence.
    """
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized or normalized.lower() in _PLACEHOLDER_IDENTIFIERS:
        return None
    if _SHORT_HEX_IDENTIFIER_PATTERN.fullmatch(normalized):
        return None
    return normalized


def _valid_shared_content_hash(value: Any) -> str | None:
    """Return a canonical cryptographic content hash, excluding perceptual hashes."""
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    return normalized if _CRYPTOGRAPHIC_HASH_PATTERN.fullmatch(normalized) else None


def derive_witness_family(event: Mapping[str, Any]) -> str:
    """Derive two-level witness family: (source kind, device).

    If the event already carries a validated Event v1.1 family, uses it.
    Otherwise derives consistently as '<source>:<device or unknown>'.
    """
    fam = event.get("family")
    if isinstance(fam, str) and fam.strip():
        return fam.strip()
    source = event.get("source") or "unknown"
    device = event.get("device") or "unknown"
    return f"{source}:{device}"


def count_independent_families(edges: Sequence[EdgeSpec]) -> int:
    """Count unique supporting witness families.

    Multiple events in the same family count once.
    """
    supporting = {
        edge.family
        for edge in edges
        if edge.role == "SUPPORTS" and edge.family
    }
    return len(supporting)


def determine_claim_status(
    supporting_families_count: int,
    has_contradiction: bool,
    is_hard_violation: bool = False,
) -> str:
    """Determine claim status according to the four allowed states:

    ASSERTED: Exactly 1 supporting witness family.
    CORROBORATED: 2 or more independent supporting families, no credible contradiction.
    CONTESTED: A credible contradiction signal exists.
    REFUTED: A hard constraint or physical law is violated.
    """
    if is_hard_violation:
        return "REFUTED"
    if has_contradiction:
        return "CONTESTED"
    if supporting_families_count >= 2:
        return "CORROBORATED"
    return "ASSERTED"


def determine_claim_grade(
    status: str,
    supporting_families_count: int,
    has_exact_identifier: bool,
) -> str:
    """Determine claim grade A, B, or C:

    Grade A: >= 2 independent witness families, exact identifier, no contradiction.
    Grade B: 1 witness family with exact identifier.
    Grade C: Weak signals, temporal-only, or contested/refuted claims.
    """
    if status in ("CONTESTED", "REFUTED"):
        return "C"
    if supporting_families_count >= 2 and has_exact_identifier and status == "CORROBORATED":
        return "A"
    if supporting_families_count >= 1 and has_exact_identifier:
        return "B"
    return "C"


def generate_same_object_flow_claims(
    promoted_links: Sequence[CandidateRelationship],
    events_by_id: Mapping[str, Mapping[str, Any]],
) -> list[ClaimSpec]:
    """Convert promoted T5 relationships into SAME_OBJECT_FLOW claims."""
    specs: list[ClaimSpec] = []

    for link in promoted_links:
        # Object-flow claims require a strong, exact shared identifier.
        if link.candidate_type != "SAME_OBJECT_FLOW":
            continue
        shared_obj = _valid_shared_object(link.canonical_entities.get("shared_object"))
        shared_hash = _valid_shared_content_hash(link.canonical_entities.get("shared_content_hash"))
        exact_identifier = shared_obj or shared_hash
        if exact_identifier is None:
            continue
        e1 = events_by_id.get(link.source_event_id)
        e2 = events_by_id.get(link.target_event_id)
        if not e1 or not e2:
            continue

        fam1 = derive_witness_family(e1)
        fam2 = derive_witness_family(e2)

        has_exact = exact_identifier is not None
        has_contradiction = len(link.contradiction_signals) > 0

        edges = [
            EdgeSpec(
                ref_kind="event",
                ref_id=e1["event_id"],
                role="SUPPORTS",
                weight=1.0,
                reason_code="SAME_OBJECT_SOURCE",
                family=fam1,
            ),
            EdgeSpec(
                ref_kind="event",
                ref_id=e2["event_id"],
                role="SUPPORTS",
                weight=1.0,
                reason_code="SAME_OBJECT_TARGET",
                family=fam2,
            ),
        ]

        fam_count = len({fam1, fam2})
        status = determine_claim_status(fam_count, has_contradiction)
        grade = determine_claim_grade(status, fam_count, has_exact)

        params = {
            "object": exact_identifier,
            "source_action": e1.get("action"),
            "target_action": e2.get("action"),
            "source_event_id": e1["event_id"],
            "target_event_id": e2["event_id"],
            "temporal_delta_seconds": round(float(link.temporal_delta), 2),
        }

        spec = ClaimSpec(
            type="SAME_OBJECT_FLOW",
            params=params,
            status=status,
            grade=grade,
            rule_id="rule_same_object_flow",
            rule_version="1.0.0",
            edges=edges,
        )
        specs.append(spec)

    return specs


def generate_offhours_session_claims(
    events: Sequence[Mapping[str, Any]],
    anomaly_findings: Sequence[Mapping[str, Any]],
    events_by_id: Mapping[str, Mapping[str, Any]],
    *,
    case_timezone: tzinfo | None = None,
    source_clocks: Mapping[str, SourceClock] | None = None,
) -> list[ClaimSpec]:
    """Convert odd-hour anomaly findings into OFFHOURS_SESSION claims.

    The local hour stored in ``params["hour"]`` is derived from the *effective*
    time interval (T2 source-clock correction) interpreted in the configured
    case timezone (``config.get_timezone()``), not from the raw UTC timestamp.
    The midpoint of the effective interval is used as the representative
    instant, consistent with how ``anomalies.find_anomalies`` evaluates the
    same events.  When clock uncertainty straddles the off-hours boundary
    (T2 status "some"), the claim grade is discounted to "C" to reflect the
    ambiguity.
    """
    specs: list[ClaimSpec] = []

    case_tz = case_timezone if case_timezone is not None else get_timezone()
    clocks = source_clocks if source_clocks is not None else load_source_clocks()
    zone = tz_label(case_tz)

    for finding in anomaly_findings:
        if finding.get("type") != "anomaly":
            continue

        for ev_id in finding.get("evidence_event_ids", []):
            ev = events_by_id.get(ev_id)
            if not ev:
                continue

            fam = derive_witness_family(ev)

            # Derive the local hour using T2 effective interval + case timezone
            hour = None
            odd_status = "all"
            from .common import normalize_events as _norm
            norm_list = _norm([ev])
            if norm_list:
                norm_ev = norm_list[0]
                iv = event_interval(norm_ev, clocks)
                local_time = to_case_time(iv.midpoint, case_tz)
                hour = local_time.hour
                odd_status = _odd_status(iv, case_tz)

            params = {
                "actor": ev.get("actor") or "unknown",
                "device": ev.get("device") or "unknown",
                "action": ev.get("action") or "unknown",
                "hour": hour if hour is not None else -1,
                "timezone": zone,
                "event_id": ev_id,
            }
            if odd_status == "some":
                params["boundary_straddle"] = True

            edges = [
                EdgeSpec(
                    ref_kind="event",
                    ref_id=ev_id,
                    role="SUPPORTS",
                    weight=1.0,
                    reason_code="ODD_HOUR_SESSION_ACTIVITY",
                    family=fam,
                )
            ]

            status = "ASSERTED"
            # Grade B for confident odd-hour activity; Grade C when clock uncertainty
            # straddles the boundary making classification ambiguous.
            grade = "C" if odd_status == "some" else "B"

            spec = ClaimSpec(
                type="OFFHOURS_SESSION",
                params=params,
                status=status,
                grade=grade,
                rule_id="rule_offhours_session",
                rule_version="1.0.0",
                edges=edges,
            )
            specs.append(spec)

    return specs


def generate_location_conflict_claims(
    contradiction_findings: Sequence[Mapping[str, Any]],
    events_by_id: Mapping[str, Mapping[str, Any]],
) -> list[ClaimSpec]:
    """Convert location contradiction findings into LOCATION_CONFLICT claims."""
    specs: list[ClaimSpec] = []

    for finding in contradiction_findings:
        if finding.get("type") != "contradiction":
            continue

        cited_ids = sorted(set(finding.get("evidence_event_ids", [])))
        if len(cited_ids) < 2:
            continue

        ev1 = events_by_id.get(cited_ids[0])
        ev2 = events_by_id.get(cited_ids[1])
        if not ev1 or not ev2:
            continue

        fam1 = derive_witness_family(ev1)
        fam2 = derive_witness_family(ev2)

        # The first event is the anchor (SUPPORTS), second event CONTRADICTS physical travel
        edges = [
            EdgeSpec(
                ref_kind="event",
                ref_id=ev1["event_id"],
                role="SUPPORTS",
                weight=1.0,
                reason_code="LOCATION_ANCHOR_RECORD",
                family=fam1,
            ),
            EdgeSpec(
                ref_kind="event",
                ref_id=ev2["event_id"],
                role="CONTRADICTS",
                weight=1.0,
                reason_code="IMPOSSIBLE_TRAVEL_SPEED_CONFLICT",
                family=fam2,
            ),
        ]

        params = {
            "event_id_1": ev1["event_id"],
            "event_id_2": ev2["event_id"],
            "location_1": ev1.get("location") or {},
            "location_2": ev2.get("location") or {},
            "time_1": ev1.get("timestamp"),
            "time_2": ev2.get("timestamp"),
        }

        spec = ClaimSpec(
            type="LOCATION_CONFLICT",
            params=params,
            status="CONTESTED",
            grade="C",
            rule_id="rule_location_conflict",
            rule_version="1.0.0",
            edges=edges,
        )
        specs.append(spec)

    return specs


# --- Contradiction gating helpers --------------------------------------------
#
# A contradiction claim is an accusation that two observations cannot both be
# true.  It must therefore rest on (a) strong evidence that both observations
# describe the SAME underlying instance/activity and (b) fully observed values
# that are genuinely incompatible.  Filename equality is NOT instance identity
# (independent archives routinely share names) and missing values are NOT
# conflicting values.

#: Values that denote an absent identity rather than an observed one.  They are
#: compared after ``normalize_actor`` / ``normalize_device`` (case-folded,
#: whitespace-collapsed).  Concrete tokens that merely *contain* such words
#: (e.g. ``unknown.65``) are observed account strings and are kept.
PLACEHOLDER_IDENTITIES = frozenset({
    "", "unknown", "null", "none", "nil", "n/a", "na", "-", "--", "?",
    "undefined", "anonymous", "unspecified", "<unknown>", "(null)", "<null>",
})

#: Raw-record keys accepted as an explicit, source-asserted session identifier.
SESSION_ID_KEYS = ("session_id",)

ARCHIVE_CREATION_ACTIONS = frozenset({"archive_create"})
TRANSFER_ACTIONS = frozenset({"file_upload", "upload"})


def observed_identity(raw: Any, normalizer: Any) -> str | None:
    """Return a normalized identity, or ``None`` when the value is missing/placeholder."""
    if not isinstance(raw, str):
        return None
    value = normalizer(raw)
    if value is None or value in PLACEHOLDER_IDENTITIES:
        return None
    return value


def explicit_session_id(event: Mapping[str, Any]) -> str | None:
    """Source-asserted session identifier from the raw record, if present and non-placeholder."""
    raw = event.get("raw")
    if not isinstance(raw, Mapping):
        return None
    for key in SESSION_ID_KEYS:
        value = raw.get(key)
        if isinstance(value, str):
            clean = value.strip()
            if clean and clean.lower() not in PLACEHOLDER_IDENTITIES:
                return clean
    return None


def _instance_keys(event: Mapping[str, Any], *, allow_session: bool) -> list[tuple[str, str]]:
    """Strong instance identifiers for an event (never a bare filename)."""
    from .entities import extract_content_hash

    keys: list[tuple[str, str]] = []
    content_hash = extract_content_hash(event)
    if content_hash:
        keys.append(("content_hash", content_hash))
    if allow_session:
        session = explicit_session_id(event)
        if session:
            keys.append(("session_id", session))
    return keys


def _record_fingerprint(event: Mapping[str, Any]) -> tuple[str, ...]:
    """Content fingerprint used to collapse exact duplicate records of one observation."""
    return (
        str(event.get("source") or ""),
        str(event.get("timestamp") or ""),
        str(event.get("action") or ""),
        str(normalize_actor(event.get("actor")) if isinstance(event.get("actor"), str) else ""),
        str(normalize_device(event.get("device")) if isinstance(event.get("device"), str) else ""),
        str(event.get("object") or ""),
        str(event.get("ip") or ""),
    )


def _safe_interval(
    event: Mapping[str, Any], clocks: Mapping[str, SourceClock]
) -> Any:
    """Effective (clock-corrected, uncertainty-widened) interval, or ``None`` if untimestamped."""
    from .common import IntelligenceError, normalize_event

    if event.get("timestamp") in (None, ""):
        return None
    try:
        norm = normalize_event(event)
    except (IntelligenceError, ValueError, TypeError):
        return None
    return event_interval(norm, clocks)


def generate_attribution_conflict_claims(
    events: Sequence[Mapping[str, Any]],
    events_by_id: Mapping[str, Mapping[str, Any]],
) -> list[ClaimSpec]:
    """Emit LOCATION_CONFLICT claims for incompatible attribution of ONE archive instance.

    Requirements (all must hold):

    1. Both events are archive-creation records.
    2. They are strongly matched to the same archive instance or session by an
       exact content hash or an explicit source-asserted ``session_id``.  A
       shared filename alone is never sufficient.
    3. They are not duplicate records of the same observation.
    4. At least one attribute (actor or device) is *observed in both* records
       (non-missing, non-placeholder) and the observed values differ.  Missing
       or placeholder values are never treated as a conflicting identity.

    Each unordered pair of distinct observations yields at most one claim.
    """
    specs: list[ClaimSpec] = []
    candidates = [
        e for e in events
        if e.get("action") in ARCHIVE_CREATION_ACTIONS and e.get("event_id")
    ]

    buckets: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for event in candidates:
        for key in _instance_keys(event, allow_session=True):
            buckets.setdefault(key, []).append(event)

    # (fingerprint_a, fingerprint_b) -> (e1, e2, match bases)
    pairs: dict[tuple[tuple[str, ...], tuple[str, ...]], dict[str, Any]] = {}
    for (basis, value), group in sorted(buckets.items()):
        ordered = sorted(group, key=lambda x: (str(x.get("timestamp")), str(x["event_id"])))
        for i, e1 in enumerate(ordered):
            for e2 in ordered[i + 1:]:
                f1, f2 = _record_fingerprint(e1), _record_fingerprint(e2)
                if f1 == f2:
                    continue  # duplicate record of one observation
                pair_key = (f1, f2) if f1 <= f2 else (f2, f1)
                entry = pairs.setdefault(pair_key, {"e1": e1, "e2": e2, "match": {}})
                entry["match"][basis] = value

    for pair_key in sorted(pairs):
        entry = pairs[pair_key]
        e1, e2 = entry["e1"], entry["e2"]
        a1 = observed_identity(e1.get("actor"), normalize_actor)
        a2 = observed_identity(e2.get("actor"), normalize_actor)
        d1 = observed_identity(e1.get("device"), normalize_device)
        d2 = observed_identity(e2.get("device"), normalize_device)

        conflicting_fields: list[str] = []
        if a1 is not None and a2 is not None and a1 != a2:
            conflicting_fields.append("actor")
        if d1 is not None and d2 is not None and d1 != d2:
            conflicting_fields.append("device")
        if not conflicting_fields:
            continue

        edges = [
            EdgeSpec(
                ref_kind="event",
                ref_id=e1["event_id"],
                role="SUPPORTS",
                weight=1.0,
                reason_code="ATTRIBUTION_CONFLICT_PRIMARY",
                family=derive_witness_family(e1),
            ),
            EdgeSpec(
                ref_kind="event",
                ref_id=e2["event_id"],
                role="CONTRADICTS",
                weight=1.0,
                reason_code="ATTRIBUTION_CONFLICT_SECONDARY",
                family=derive_witness_family(e2),
            ),
        ]
        params = {
            "object": normalize_file_object(e1.get("object"), action=e1.get("action")),
            "conflict_type": "actor_device_attribution_conflict",
            "instance_match": dict(sorted(entry["match"].items())),
            "conflicting_fields": conflicting_fields,
            "actor_1": a1,
            "device_1": d1,
            "actor_2": a2,
            "device_2": d2,
            "time_1": e1.get("timestamp"),
            "time_2": e2.get("timestamp"),
        }
        specs.append(
            ClaimSpec(
                type="LOCATION_CONFLICT",
                params=params,
                status="CONTESTED",
                grade="C",
                rule_id="rule_attribution_conflict",
                rule_version="2.0.0",
                edges=edges,
            )
        )
    return specs


def generate_cross_source_temporal_conflict_claims(
    events: Sequence[Mapping[str, Any]],
    events_by_id: Mapping[str, Mapping[str, Any]],
    *,
    source_clocks: Mapping[str, SourceClock] | None = None,
) -> list[ClaimSpec]:
    """Emit LOCATION_CONFLICT claims only for a documented temporal invariant violation.

    Documented invariant TC-1 (creation precedes transfer):
        An object instance cannot be transferred before it exists.  If an
        archive-creation record and a transfer (upload) record refer to the SAME
        object instance - established by an exact content hash, never by
        filename - and the transfer's effective interval is *definitely before*
        the creation's effective interval, the two observations are temporally
        incompatible.

    Effective intervals come from the T2 timeline model (raw timestamp parsed
    under the UTC-naive policy, source-clock offset removed, widened by source
    uncertainty).  Only ``definitely_before`` (A.hi < B.lo) counts; overlapping
    or uncertain intervals never produce a claim.  Events without a parseable
    timestamp are ignored.

    Not supported (missing prerequisite): the repository defines no invariant
    relating ``session_refresh`` to uploads, nor any shared activity identifier
    that would prove two cross-source records witness the same single activity.
    Such pairs - including same-filename upload/session-refresh sequences - are
    therefore never reported as contradictions.
    """
    clocks = source_clocks if source_clocks is not None else load_source_clocks()
    specs: list[ClaimSpec] = []

    creations: dict[str, list[Mapping[str, Any]]] = {}
    transfers: dict[str, list[Mapping[str, Any]]] = {}
    for event in events:
        if not event.get("event_id"):
            continue
        action = event.get("action")
        if action in ARCHIVE_CREATION_ACTIONS:
            target = creations
        elif action in TRANSFER_ACTIONS:
            target = transfers
        else:
            continue
        for basis, value in _instance_keys(event, allow_session=False):
            if basis == "content_hash":
                target.setdefault(value, []).append(event)

    seen: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    for content_hash in sorted(set(creations) & set(transfers)):
        for creation in sorted(creations[content_hash], key=lambda x: str(x["event_id"])):
            c_iv = _safe_interval(creation, clocks)
            if c_iv is None:
                continue
            for transfer in sorted(transfers[content_hash], key=lambda x: str(x["event_id"])):
                t_iv = _safe_interval(transfer, clocks)
                if t_iv is None or not t_iv.definitely_before(c_iv):
                    continue
                key = (_record_fingerprint(creation), _record_fingerprint(transfer))
                if key in seen:
                    continue
                seen.add(key)
                edges = [
                    EdgeSpec(
                        ref_kind="event",
                        ref_id=creation["event_id"],
                        role="SUPPORTS",
                        weight=1.0,
                        reason_code="TEMPORAL_CONFLICT_CREATION",
                        family=derive_witness_family(creation),
                    ),
                    EdgeSpec(
                        ref_kind="event",
                        ref_id=transfer["event_id"],
                        role="CONTRADICTS",
                        weight=1.0,
                        reason_code="TEMPORAL_CONFLICT_TRANSFER_BEFORE_CREATION",
                        family=derive_witness_family(transfer),
                    ),
                ]
                params = {
                    "object": content_hash,
                    "conflict_type": "cross_source_timestamp_disagreement",
                    "invariant": "TC-1_creation_precedes_transfer",
                    "creation_event_id": creation["event_id"],
                    "transfer_event_id": transfer["event_id"],
                    "creation_interval": [c_iv.lo.isoformat(), c_iv.hi.isoformat()],
                    "transfer_interval": [t_iv.lo.isoformat(), t_iv.hi.isoformat()],
                    "min_violation_seconds": round((c_iv.lo - t_iv.hi).total_seconds(), 3),
                }
                specs.append(
                    ClaimSpec(
                        type="LOCATION_CONFLICT",
                        params=params,
                        status="CONTESTED",
                        grade="C",
                        rule_id="rule_cross_source_temporal_conflict",
                        rule_version="2.0.0",
                        edges=edges,
                    )
                )
    return specs


def generate_actor_device_consistent_claims(
    events: Sequence[Mapping[str, Any]],
    events_by_id: Mapping[str, Mapping[str, Any]],
) -> list[ClaimSpec]:
    """Emit ACTOR_DEVICE_CONSISTENT claims when corroborated across events.

    Grading is routed through the standard shared grading policy
    (``determine_claim_grade``):
    - Grade A: >= 2 independent witness families AND exact identifier.
    - Grade B: 1 witness family AND exact identifier (insufficient independent
      corroboration to achieve Grade A).
    - Grade C: Generic/non-exact identifiers or contested claims.
    """
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = {}

    for ev in events:
        raw_act = ev.get("actor")
        raw_dev = ev.get("device")
        norm_act = normalize_actor(raw_act) if isinstance(raw_act, str) else None
        norm_dev = normalize_device(raw_dev) if isinstance(raw_dev, str) else None

        if norm_act and norm_dev:
            groups.setdefault((norm_act, norm_dev), []).append(ev)

    GENERIC_NAMES = frozenset({"unknown", "none", "anonymous", "null", "undefined", ""})

    specs: list[ClaimSpec] = []
    for (act, dev), ev_list in sorted(groups.items()):
        # Require observation in at least 2 events to assert consistency
        if len(ev_list) < 2:
            continue

        families = {derive_witness_family(e) for e in ev_list}
        family_count = len(families)

        edges = [
            EdgeSpec(
                ref_kind="event",
                ref_id=e["event_id"],
                role="SUPPORTS",
                weight=1.0,
                reason_code="CORROBORATING_ACTOR_DEVICE",
                family=derive_witness_family(e),
            )
            for e in sorted(ev_list, key=lambda x: str(x.get("event_id")))
        ]

        # Exact identifier check: neither actor nor device is a generic placeholder
        has_exact = (
            bool(act) and act.lower() not in GENERIC_NAMES and
            bool(dev) and dev.lower() not in GENERIC_NAMES
        )

        status = determine_claim_status(family_count, has_contradiction=False)
        grade = determine_claim_grade(status, family_count, has_exact)

        params = {
            "actor": act,
            "device": dev,
            "supporting_families_count": family_count,
        }

        spec = ClaimSpec(
            type="ACTOR_DEVICE_CONSISTENT",
            params=params,
            status=status,
            grade=grade,
            rule_id="rule_actor_device_consistent",
            rule_version="1.0.0",
            edges=edges,
        )
        specs.append(spec)

    return specs


def generate_session_origin_mismatch_claims(
    events: Sequence[Mapping[str, Any]],
    events_by_id: Mapping[str, Mapping[str, Any]],
) -> list[ClaimSpec]:
    """Emit SESSION_ORIGIN_MISMATCH claims when cross-source network origins clash."""
    specs: list[ClaimSpec] = []
    # Index events with same actor and device occurring within a tight 5-minute window
    by_actor_dev: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    for e in events:
        a = normalize_actor(e.get("actor"))
        d = normalize_device(e.get("device"))
        if a and d and e.get("ip"):
            by_actor_dev.setdefault((a, d), []).append(e)

    for (act, dev), group in sorted(by_actor_dev.items()):
        if len(group) < 2:
            continue
        group_sorted = sorted(group, key=lambda x: str(x.get("timestamp")))
        for i in range(len(group_sorted)):
            e1 = group_sorted[i]
            for j in range(i + 1, len(group_sorted)):
                e2 = group_sorted[j]
                ip1 = e1.get("ip")
                ip2 = e2.get("ip")
                if ip1 and ip2 and ip1 != ip2:
                    # Check time difference (within 5 minutes)
                    try:
                        t1 = datetime.fromisoformat(str(e1.get("timestamp")).replace("Z", "+00:00"))
                        t2 = datetime.fromisoformat(str(e2.get("timestamp")).replace("Z", "+00:00"))
                        diff = abs((t2 - t1).total_seconds())
                    except Exception:
                        diff = 999999

                    if diff <= 300:
                        fam1 = derive_witness_family(e1)
                        fam2 = derive_witness_family(e2)
                        params = {
                            "actor": act,
                            "device": dev,
                            "ip_1": ip1,
                            "ip_2": ip2,
                            "temporal_delta_seconds": round(diff, 2),
                        }
                        edges = [
                            EdgeSpec(
                                ref_kind="event",
                                ref_id=e1["event_id"],
                                role="SUPPORTS",
                                weight=1.0,
                                reason_code="SESSION_ORIGIN_PRIMARY",
                                family=fam1,
                            ),
                            EdgeSpec(
                                ref_kind="event",
                                ref_id=e2["event_id"],
                                role="CONTRADICTS",
                                weight=1.0,
                                reason_code="SESSION_ORIGIN_CONFLICT",
                                family=fam2,
                            ),
                        ]
                        specs.append(ClaimSpec(
                            type="SESSION_ORIGIN_MISMATCH",
                            params=params,
                            status="CONTESTED",
                            grade="C",
                            rule_id="rule_session_origin_mismatch",
                            rule_version="1.0.0",
                            edges=edges,
                        ))
    return specs


def generate_no_record_in_covered_window_claims(
    events: Sequence[Mapping[str, Any]],
    expected_gaps: Sequence[Mapping[str, Any]] = (),
) -> list[ClaimSpec]:
    """Emit NO_RECORD_IN_COVERED_WINDOW claims for demonstrably covered windows."""
    specs: list[ClaimSpec] = []
    for gap in expected_gaps:
        source = gap.get("source")
        window_start = gap.get("window_start")
        window_end = gap.get("window_end")
        expected_action = gap.get("expected_action")
        boundary_event_ids = gap.get("boundary_event_ids", [])

        if not (source and window_start and window_end and expected_action and boundary_event_ids):
            continue

        edges = [
            EdgeSpec(
                ref_kind="event",
                ref_id=eid,
                role="SUPPORTS",
                weight=1.0,
                reason_code="COVERAGE_WINDOW_BOUNDARY",
                family=f"{source}:boundary",
            )
            for eid in boundary_event_ids
        ]

        params = {
            "source": source,
            "expected_action": expected_action,
            "window_start": window_start,
            "window_end": window_end,
        }
        specs.append(ClaimSpec(
            type="NO_RECORD_IN_COVERED_WINDOW",
            params=params,
            status="ASSERTED",
            grade="B",
            rule_id="rule_no_record_in_covered_window",
            rule_version="1.0.0",
            edges=edges,
        ))
    return specs


def generate_claims(
    events: Sequence[Mapping[str, Any]],
    *,
    promoted_links: Sequence[CandidateRelationship] | None = None,
    anomaly_findings: Sequence[Mapping[str, Any]] | None = None,
    contradiction_findings: Sequence[Mapping[str, Any]] | None = None,
    expected_gaps: Sequence[Mapping[str, Any]] = (),
    case_timezone: tzinfo | None = None,
    source_clocks: Mapping[str, SourceClock] | None = None,
) -> list[ClaimSpec]:
    """Orchestrate rule-driven claim generation across all supported claim types.

    Deterministic execution, independent of event insertion order.
    """
    if not events:
        return []

    events_by_id = {e["event_id"]: e for e in events if "event_id" in e}

    # 1. T5 Correlation links -> SAME_OBJECT_FLOW
    if promoted_links is None:
        _, promoted_links = generate_candidates(events, source_clocks=source_clocks)
    same_object_claims = generate_same_object_flow_claims(promoted_links, events_by_id)

    # 2. Anomalies -> OFFHOURS_SESSION
    if anomaly_findings is None:
        anomaly_findings = find_anomalies(
            list(events), case_timezone=case_timezone, source_clocks=source_clocks
        )
    offhours_claims = generate_offhours_session_claims(
        events,
        anomaly_findings,
        events_by_id,
        case_timezone=case_timezone,
        source_clocks=source_clocks,
    )

    # 3. Contradictions -> LOCATION_CONFLICT
    if contradiction_findings is None:
        contradiction_findings = find_contradictions(list(events))
    location_claims = generate_location_conflict_claims(contradiction_findings, events_by_id)
    attribution_claims = generate_attribution_conflict_claims(events, events_by_id)
    temporal_claims = generate_cross_source_temporal_conflict_claims(
        events, events_by_id, source_clocks=source_clocks
    )

    # 4. Multi-source bindings -> ACTOR_DEVICE_CONSISTENT
    actor_device_claims = generate_actor_device_consistent_claims(events, events_by_id)

    # 5. Network clashes -> SESSION_ORIGIN_MISMATCH
    origin_claims = generate_session_origin_mismatch_claims(events, events_by_id)

    # 6. Absence in window -> NO_RECORD_IN_COVERED_WINDOW
    no_record_claims = generate_no_record_in_covered_window_claims(events, expected_gaps)

    all_specs = (
        same_object_claims
        + offhours_claims
        + location_claims
        + attribution_claims
        + temporal_claims
        + actor_device_claims
        + origin_claims
        + no_record_claims
    )

    # Deterministic total sorting of claims
    all_specs.sort(
        key=lambda s: (
            s.type,
            s.rule_id,
            s.rule_version,
            json.dumps(s.params, sort_keys=True),
        )
    )

    return all_specs
