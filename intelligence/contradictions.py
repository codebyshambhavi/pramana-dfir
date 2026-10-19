"""Deterministic cross-source contradiction detection for Role 2.

This module implements the supported location-vs-time/travel-speed rule.
It does not geolocate IPs, infer addresses, or use external services.
"""
from __future__ import annotations

from math import atan2, cos, radians, sin, sqrt
from typing import Any

from . import common
from .config import MAX_PLAUSIBLE_SPEED_KMH

_EARTH_RADIUS_KM = 6371.008


def _distance_km(
    first: tuple[float, float], second: tuple[float, float]
) -> float:
    """Return the great-circle distance between two (lat, lon) points."""
    lat1, lon1 = map(radians, first)
    lat2, lon2 = map(radians, second)
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    h = (
        sin(dlat / 2) ** 2
        + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    )
    return 2 * _EARTH_RADIUS_KM * atan2(
        sqrt(h), sqrt(max(0.0, 1.0 - h))
    )


def find_contradictions(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return deterministic contradiction Findings for implausible travel speed.

    Only events from the same case with valid latitude/longitude values are
    compared. A finding is emitted when the implied travel speed is strictly
    greater than ``MAX_PLAUSIBLE_SPEED_KMH``.
    """
    if not events:
        return []

    normalized = common.normalize_events(events)
    known_event_ids = common.extract_event_ids(events)

    by_case: dict[str, list[common.NormalizedEvent]] = {}
    for event in normalized:
        case_id = event.case_id or ""
        by_case.setdefault(case_id, []).append(event)

    findings: list[dict[str, Any]] = []

    for case_id in sorted(by_case):
        located = [
            event for event in by_case[case_id] if event.location is not None
        ]

        for index, first in enumerate(located):
            for second in located[index + 1:]:
                delta_seconds = (
                    second.timestamp - first.timestamp
                ).total_seconds()
                if delta_seconds < 0:
                    continue

                distance_km = _distance_km(first.location, second.location)
                if distance_km == 0:
                    continue

                if delta_seconds == 0:
                    speed_kmh = float("inf")
                else:
                    speed_kmh = distance_km / (delta_seconds / 3600.0)

                if speed_kmh <= MAX_PLAUSIBLE_SPEED_KMH:
                    continue

                speed_text = (
                    "infinite"
                    if speed_kmh == float("inf")
                    else f"{speed_kmh:.1f}"
                )
                claim = (
                    f"Events {first.event_id} and {second.event_id} imply "
                    f"travel of approximately {speed_text} km/h, exceeding "
                    f"the configured maximum plausible speed of "
                    f"{MAX_PLAUSIBLE_SPEED_KMH:.1f} km/h."
                )
                reasoning = (
                    f"Event {first.event_id} occurred at "
                    f"{first.timestamp.isoformat()} at location "
                    f"{first.location}; event {second.event_id} occurred "
                    f"at {second.timestamp.isoformat()} at location "
                    f"{second.location}. The locations are approximately "
                    f"{distance_km:.1f} km apart over {delta_seconds:.1f} "
                    f"seconds, implying about {speed_text} km/h. This "
                    f"exceeds the configured threshold and requires "
                    f"investigation; it does not by itself establish fraud."
                )

                findings.append(
                    common.make_finding(
                        case_id=case_id,
                        finding_type="contradiction",
                        rule_id="location_travel_speed",
                        claim=claim,
                        confidence=0.95,
                        evidence_event_ids=[
                            first.event_id,
                            second.event_id,
                        ],
                        reasoning=reasoning,
                        known_event_ids=known_event_ids,
                        needs_human_review=True,
                    )
                )

    return sorted(findings, key=lambda finding: finding["finding_id"])
