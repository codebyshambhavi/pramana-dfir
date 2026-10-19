"""Role 2: rule-based anomalies (odd-hour login, unusual extension, burst of file access).

"""

from __future__ import annotations

from typing import Any

from . import common
from .config import ODD_HOUR_END, ODD_HOUR_START


def find_anomalies(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return anomaly Findings for events occurring during odd hours.

    Args:
        events: List of Event dictionaries (as per contracts/event.schema.json).

    Returns:
        List of Finding dictionaries (as per contracts/finding.schema.json).
        Each Finding has type="anomaly".
    """
    if not events:
        return []

    # Normalize events to ensure deterministic order and proper timestamp handling
    normalized_events = common.normalize_events(events)

    # Extract known event IDs for finding validation
    known_event_ids = common.extract_event_ids(events)

    findings: list[dict[str, Any]] = []

    for event in normalized_events:
        # Check if event timestamp falls within odd hours range
        # ODD_HOUR_START and ODD_HOUR_END define a half-open range [start, end)
        event_hour = event.timestamp.hour

        # Handle the case where range wraps around midnight (start > end)
        if ODD_HOUR_START < ODD_HOUR_END:
            # Normal case: start < end, e.g., [0, 5) for 00:00-04:59
            is_odd_hour = ODD_HOUR_START <= event_hour < ODD_HOUR_END
        else:
            # Wraparound case: start > end, e.g., [22, 5) for 22:00-04:59
            is_odd_hour = event_hour >= ODD_HOUR_START or event_hour < ODD_HOUR_END

        if is_odd_hour:
            # Build an anomaly finding for this event
            claim = (
                f"Event occurred during the configured odd hours period "
                f"[{ODD_HOUR_START:02d}:00, {ODD_HOUR_END:02d}:00) UTC."
            )
            reasoning = (
                f"Event {event.event_id} ({event.source}:{event.action}) "
                f"occurred at {event.timestamp.isoformat()}, which is during "
                f"the configured odd-hours period "
                f"[{ODD_HOUR_START:02d}:00, {ODD_HOUR_END:02d}:00) UTC."
            )

            finding = common.make_finding(
                case_id=event.case_id or "",
                finding_type="anomaly",
                rule_id="odd_hour_activity",
                claim=claim,
                confidence=0.7,  # Deterministic confidence for odd-hour detection
                evidence_event_ids=[event.event_id],
                reasoning=reasoning,
                known_event_ids=known_event_ids,
                needs_human_review=True,
            )

            findings.append(finding)

    return findings