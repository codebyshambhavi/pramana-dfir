"""Role 2: event-based image authenticity triage.

The Event contract does not define raw EXIF/perceptual-hash keys, so this module
uses only signals that can be supported by normalized Event fields: source-file
hash consistency, metadata consistency across repeated references, and
provenance. Perceptual matching is reported as unavailable rather than invented.

This is triage only. It never emits the word "fake".
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Mapping

from .common import make_finding, normalize_events

_IMAGE_SOURCE = "image"
_SHA256_LENGTH = 64


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _SHA256_LENGTH
        and all(ch in "0123456789abcdef" for ch in value)
    )


def _group_key(event) -> str:
    if event.artifact_ref:
        return f"artifact:{event.artifact_ref}"
    if event.object:
        return f"object:{event.object}"
    return f"event:{event.event_id}"


def _build_signals(image_events) -> list[dict[str, Any]]:
    groups: dict[str, list[Any]] = defaultdict(list)
    for event in image_events:
        groups[_group_key(event)].append(event)

    hash_conflicts = 0
    hash_checked = 0
    metadata_conflicts = 0
    metadata_checked = 0

    for grouped in groups.values():
        hashes = {e.sha256 for e in grouped if _valid_sha256(e.sha256)}
        invalid_hashes = [
            e for e in grouped if e.sha256 is not None and not _valid_sha256(e.sha256)
        ]
        if hashes or invalid_hashes:
            hash_checked += 1
            if invalid_hashes or len(hashes) > 1:
                hash_conflicts += 1

        locations = {e.location for e in grouped if e.location is not None}
        if len(locations) > 1:
            metadata_checked += 1
            metadata_conflicts += 1
        elif len(grouped) > 1:
            metadata_checked += 1

    missing_provenance = [
        e.event_id for e in image_events if not e.evidence_id or not e.artifact_ref
    ]

    if hash_checked:
        hash_signal = {
            "name": "hash_consistency",
            "status": "conflict" if hash_conflicts else "pass",
            "detail": (
                "Repeated image references do not have consistent source-file hashes."
                if hash_conflicts
                else "Available source-file hashes are valid and consistent within repeated image references."
            ),
        }
    else:
        hash_signal = {
            "name": "hash_consistency",
            "status": "unavailable",
            "detail": "No usable source-file SHA-256 signal was available.",
        }

    if metadata_checked:
        metadata_signal = {
            "name": "metadata_consistency",
            "status": "conflict" if metadata_conflicts else "pass",
            "detail": (
                "Repeated image references contain conflicting normalized location metadata."
                if metadata_conflicts
                else "Repeated image references have consistent normalized metadata."
            ),
        }
    else:
        metadata_signal = {
            "name": "metadata_consistency",
            "status": "unavailable",
            "detail": "No repeated image reference was available for an event-level metadata comparison.",
        }

    perceptual_signal = {
        "name": "perceptual_match",
        "status": "unavailable",
        "detail": "The Event contract does not expose a documented perceptual-hash or known-source match signal.",
    }

    provenance_signal = {
        "name": "provenance",
        "status": "conflict" if missing_provenance else "pass",
        "detail": (
            f"Image event(s) lack evidence_id or artifact_ref: {', '.join(sorted(missing_provenance))}."
            if missing_provenance
            else "Every image event has an evidence_id and artifact_ref."
        ),
    }

    return [hash_signal, metadata_signal, perceptual_signal, provenance_signal]


def _rating(signals: list[dict[str, Any]]) -> tuple[str, str]:
    conflicts = sum(s["status"] == "conflict" for s in signals)
    unavailable = sum(s["status"] == "unavailable" for s in signals)
    if conflicts >= 2:
        return "low", "Multiple authenticity signals conflict."
    if conflicts == 1:
        return "medium", "One authenticity signal conflicts; further verification is required."
    if unavailable >= 2:
        return "medium", "Multiple authenticity signals are unavailable from the Event contract."
    return "high", "The available event-based authenticity signals are consistent."


def score_image(events: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Return an event-based image triage result plus one hypothesis Finding."""
    normalized = [e for e in normalize_events(events) if e.source == _IMAGE_SOURCE]
    if not normalized:
        raise ValueError("score_image requires at least one image Event")

    signals = _build_signals(normalized)
    rating, reason = _rating(signals)
    event_ids = [e.event_id for e in normalized]
    case_id = normalized[0].case_id or ""

    finding = make_finding(
        case_id=case_id,
        finding_type="hypothesis",
        rule_id="image_authenticity_triage",
        claim=f"Image authenticity triage is rated {rating}; further verification is required before drawing a conclusion.",
        confidence={"high": 0.85, "medium": 0.65, "low": 0.45}[rating],
        evidence_event_ids=event_ids,
        reasoning=reason,
        known_event_ids=event_ids,
        needs_human_review=True,
    )

    return {"rating": rating, "signals": signals, "reason": reason, "finding": finding}
