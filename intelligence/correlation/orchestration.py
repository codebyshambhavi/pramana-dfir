"""Stage 5 deterministic orchestration for the PRAMANA correlation engine."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .anchors import evaluate_anchors, generate_candidate_pairs
from .explain import explain_primary, explain_secondary
from .fields import resolve_event
from .registry import Registry
from .scorer import score_pair


class CorrelationInputError(ValueError):
    """Input events cannot safely be correlated."""


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _relationship_id(payload: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()
    return f"rel_{digest}"


def _event_key(event: Mapping[str, Any]) -> tuple[str, str]:
    return str(event.get("case_id") or ""), str(event.get("event_id") or "")


def _evidence_pointer(event: Mapping[str, Any], resolved: Mapping[str, Any]) -> dict[str, Any]:
    pointers: dict[str, Any] = {
        "evidence_id": event.get("evidence_id"),
        "artifact_ref": event.get("artifact_ref"),
        "source": event.get("source"),
    }
    locators = sorted({
        str(field.source_locator)
        for field in resolved.values()
        if getattr(field, "source_locator", None)
    })
    if locators:
        pointers["source_locators"] = locators
    return {k: v for k, v in pointers.items() if v is not None}


def _validate_events(events: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    if isinstance(events, (str, bytes)):
        raise CorrelationInputError("events must be a sequence of event mappings")
    cleaned: list[Mapping[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, event in enumerate(events):
        if not isinstance(event, Mapping):
            raise CorrelationInputError(f"events[{index}] must be a mapping")
        case_id, event_id = _event_key(event)
        if not case_id:
            raise CorrelationInputError(f"events[{index}] is missing case_id; refusing unscoped correlation")
        if not event_id:
            raise CorrelationInputError(f"events[{index}] is missing event_id")
        key = (case_id, event_id)
        if key in seen:
            raise CorrelationInputError(f"duplicate event_id {event_id!r} within case {case_id!r}")
        seen.add(key)
        if not event.get("source"):
            raise CorrelationInputError(f"event {event_id!r} is missing source")
        cleaned.append(event)
    return cleaned


@dataclass(frozen=True)
class CorrelationResult:
    relationships: tuple[Mapping[str, Any], ...]
    metadata: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"relationships": [dict(x) for x in self.relationships], "metadata": dict(self.metadata)}

    @property
    def relationship_count(self) -> int:
        return len(self.relationships)


def correlate_relationships(
    events: Sequence[Mapping[str, Any]],
    registry: Registry,
    source_clocks: Mapping[str, Any] | None = None,
    evidence_context: Mapping[str, Mapping[str, Any]] | None = None,
) -> CorrelationResult:
    """Correlate events using validated direct anchors and registry-scored context.

    Mixed-case input is allowed, but candidate generation and every emitted
    relationship are strictly case-scoped. An event without a case identifier
    is rejected rather than silently placed in a global/default case.
    """
    if not isinstance(registry, Registry):
        raise CorrelationInputError("registry must be a validated Registry instance")
    event_list = _validate_events(events)
    clocks = source_clocks or {}

    # Resolve all canonical fields once for traceability and fail early on malformed input.
    resolved_by_key = {
        _event_key(event): resolve_event(
            event,
            source_clock=clocks.get(str(event.get("source"))),
            evidence_context=evidence_context,
        )
        for event in event_list
    }

    pairs, candidate_meta = generate_candidate_pairs(event_list, registry)
    relationships: list[dict[str, Any]] = []
    primary_count = secondary_count = below_threshold_count = rejected_anchor_count = 0

    for a, b in pairs:
        case_a, event_a = _event_key(a)
        case_b, event_b = _event_key(b)
        if case_a != case_b:  # defence in depth; candidate generator is also case-scoped
            continue
        # Canonical orientation makes IDs and explanations independent of input order.
        if event_b < event_a:
            a, b = b, a
            event_a, event_b = event_b, event_a
        anchors = evaluate_anchors(a, b, registry, evidence_context=evidence_context)
        anchored = [x for x in anchors if x.status == "ANCHORED"]
        rejected_anchor_count += sum(x.status == "REJECTED" for x in anchors)
        evidence_a = _evidence_pointer(a, resolved_by_key[(case_a, event_a)])
        evidence_b = _evidence_pointer(b, resolved_by_key[(case_b, event_b)])

        if anchored:
            anchor_dicts = [x.to_dict() for x in anchored]
            id_payload = {
                "case_id": case_a, "source_event_id": event_a, "target_event_id": event_b,
                "relationship_type": "PRIMARY", "anchor_parameter_ids": sorted(x.parameter_id for x in anchored),
                "registry_hash": registry.registry_hash,
            }
            relationships.append({
                "relationship_id": _relationship_id(id_payload),
                "case_id": case_a,
                "source_event_id": event_a,
                "target_event_id": event_b,
                "relationship_type": "PRIMARY",
                "status": "VALIDATED_DIRECT",
                "confidence": "DIRECT",
                "score": None,
                "anchor_type": sorted({x.anchor_type for x in anchored}),
                "anchors": anchor_dicts,
                "feature_contributions": [],
                "counter_signals": [],
                "evidence_pointers": {"source": evidence_a, "target": evidence_b},
                "explanation": explain_primary(anchor_dicts),
                "registry_version": registry.registry_version,
                "registry_hash": registry.registry_hash,
                "config_version": registry.config_version,
                "calibration_status": registry.calibration_status,
                "thresholds": None,
            })
            primary_count += 1
            # A direct anchor is represented once as PRIMARY, not duplicated as SECONDARY.
            continue

        case_events = [event for event in event_list if event.get("case_id") == case_a]
        scored = score_pair(a, b, registry, events=case_events, clocks=clocks, evidence_context=evidence_context)
        if scored["status"] == "BELOW_THRESHOLD":
            below_threshold_count += 1
            continue
        id_payload = {
            "case_id": case_a, "source_event_id": event_a, "target_event_id": event_b,
            "relationship_type": "SECONDARY", "score": scored["score"],
            "feature_contributions": scored["feature_contributions"],
            "counter_signals": scored["counter_signals"], "registry_hash": registry.registry_hash,
        }
        relationships.append({
            "relationship_id": _relationship_id(id_payload),
            "case_id": case_a,
            "source_event_id": event_a,
            "target_event_id": event_b,
            "relationship_type": "SECONDARY",
            "status": scored["status"],
            "confidence": scored["status"],
            "score": scored["score"],
            "raw_score": scored["raw_score"],
            "anchor_type": [],
            "anchors": [x.to_dict() for x in anchors if x.status == "REJECTED"],
            "feature_contributions": scored["feature_contributions"],
            "counter_signals": scored["counter_signals"],
            "unavailable_parameters": scored["unavailable_parameters"],
            "blocked_parameters": scored["blocked_parameters"],
            "reliability_factors": scored["reliability_factors"],
            "evidence_pointers": {"source": evidence_a, "target": evidence_b},
            "explanation": explain_secondary(scored),
            "registry_version": scored["registry_version"],
            "registry_hash": scored["registry_hash"],
            "config_version": scored["config_version"],
            "calibration_status": scored["calibration_status"],
            "thresholds": scored["thresholds"],
        })
        secondary_count += 1

    relationships.sort(key=lambda r: (
        str(r["case_id"]), str(r["source_event_id"]), str(r["target_event_id"]),
        str(r["relationship_type"]), str(r["relationship_id"]),
    ))
    metadata = {
        "event_count": len(event_list),
        "candidate_pair_count": candidate_meta["candidate_pair_count"],
        "relationship_count": len(relationships),
        "primary_relationship_count": primary_count,
        "secondary_relationship_count": secondary_count,
        "below_threshold_pair_count": below_threshold_count,
        "rejected_anchor_count": rejected_anchor_count,
        "bucket_count": candidate_meta["bucket_count"],
        "skipped_buckets": candidate_meta["skipped_buckets"],
        "max_bucket_size": candidate_meta["max_bucket_size"],
        "time_window_seconds": candidate_meta["time_window_seconds"],
        "registry_version": registry.registry_version,
        "registry_hash": registry.registry_hash,
        "config_version": registry.config_version,
        "calibration_status": registry.calibration_status,
        "threshold_status": "PROVISIONAL" if registry.is_provisional else "CALIBRATED",
    }
    return CorrelationResult(tuple(relationships), metadata)
