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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from .anomalies import find_anomalies
from .contradictions import find_contradictions
from .correlate import CandidateRelationship, generate_candidates
from .entities import normalize_actor, normalize_device

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
CLAIM_STATUSES = ("ASSERTED", "CORROBORATED", "CONTESTED", "REFUTED")
CLAIM_GRADES = ("A", "B", "C")
EDGE_ROLES = ("SUPPORTS", "CONTRADICTS")


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
        e1 = events_by_id.get(link.source_event_id)
        e2 = events_by_id.get(link.target_event_id)
        if not e1 or not e2:
            continue

        fam1 = derive_witness_family(e1)
        fam2 = derive_witness_family(e2)

        has_exact = bool(
            link.canonical_entities.get("shared_object")
            or link.canonical_entities.get("shared_content_hash")
        )
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

        shared_obj = (
            link.canonical_entities.get("shared_object")
            or link.canonical_entities.get("shared_content_hash")
            or "unknown"
        )

        params = {
            "object": shared_obj,
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
) -> list[ClaimSpec]:
    """Convert odd-hour anomaly findings into OFFHOURS_SESSION claims."""
    specs: list[ClaimSpec] = []

    for finding in anomaly_findings:
        if finding.get("type") != "anomaly":
            continue

        for ev_id in finding.get("evidence_event_ids", []):
            ev = events_by_id.get(ev_id)
            if not ev:
                continue

            fam = derive_witness_family(ev)
            raw_ts = ev.get("timestamp")
            hour = None
            if isinstance(raw_ts, str):
                try:
                    dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
                    hour = dt.hour
                except Exception:
                    pass

            params = {
                "actor": ev.get("actor") or "unknown",
                "device": ev.get("device") or "unknown",
                "action": ev.get("action") or "unknown",
                "hour": hour if hour is not None else -1,
                "event_id": ev_id,
            }

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
            grade = "B"

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


def generate_actor_device_consistent_claims(
    events: Sequence[Mapping[str, Any]],
    events_by_id: Mapping[str, Mapping[str, Any]],
) -> list[ClaimSpec]:
    """Emit ACTOR_DEVICE_CONSISTENT claims when corroborated across independent sources."""
    groups: dict[tuple[str, str], list[Mapping[str, Any]]] = {}

    for ev in events:
        raw_act = ev.get("actor")
        raw_dev = ev.get("device")
        norm_act = normalize_actor(raw_act) if isinstance(raw_act, str) else None
        norm_dev = normalize_device(raw_dev) if isinstance(raw_dev, str) else None

        if norm_act and norm_dev:
            groups.setdefault((norm_act, norm_dev), []).append(ev)

    specs: list[ClaimSpec] = []
    for (act, dev), ev_list in sorted(groups.items()):
        families = {derive_witness_family(e) for e in ev_list}
        # Only claim consistency if observed in at least 2 events across at least 2 families
        if len(ev_list) >= 2 and len(families) >= 2:
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
            params = {
                "actor": act,
                "device": dev,
                "supporting_families_count": len(families),
            }
            spec = ClaimSpec(
                type="ACTOR_DEVICE_CONSISTENT",
                params=params,
                status="CORROBORATED",
                grade="A",
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
) -> list[ClaimSpec]:
    """Orchestrate rule-driven claim generation across all supported claim types.

    Deterministic execution, independent of event insertion order.
    """
    if not events:
        return []

    events_by_id = {e["event_id"]: e for e in events if "event_id" in e}

    # 1. T5 Correlation links -> SAME_OBJECT_FLOW
    if promoted_links is None:
        _, promoted_links = generate_candidates(events)
    same_object_claims = generate_same_object_flow_claims(promoted_links, events_by_id)

    # 2. Anomalies -> OFFHOURS_SESSION
    if anomaly_findings is None:
        anomaly_findings = find_anomalies(list(events))
    offhours_claims = generate_offhours_session_claims(events, anomaly_findings, events_by_id)

    # 3. Contradictions -> LOCATION_CONFLICT
    if contradiction_findings is None:
        contradiction_findings = find_contradictions(list(events))
    location_claims = generate_location_conflict_claims(contradiction_findings, events_by_id)

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
