"""Role 2: deterministic evidence correlation.

Correlates events that refer to the same object and occur within a configurable
time window. Special handling for archive-upload pairs with a longer window.

The output is a list of schema-valid Finding objects with type="correlation".
"""

from __future__ import annotations

from typing import Any

from . import common
from .config import DEFAULT_CORRELATION_WINDOW, ARCHIVE_UPLOAD_WINDOW


def correlate(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return correlation Findings for events with same object within time windows.

    Args:
        events: List of Event dictionaries (as per contracts/event.schema.json).

    Returns:
        List of Finding dictionaries (as per contracts/finding.schema.json).
        Each Finding has type="correlation".
    """
    if len(events) < 2:
        return []

    # Normalize and sort events chronologically (by timestamp, then event_id).
    # This ensures deterministic order.
    normalized_events = common.normalize_events(events)

    # Configuration windows in minutes.
    general_window_minutes = DEFAULT_CORRELATION_WINDOW.total_seconds() // 60
    archive_upload_window_minutes = ARCHIVE_UPLOAD_WINDOW.total_seconds() // 60

    findings: list[dict[str, Any]] = []

    # We assume all events belong to the same case. Take case_id from the first event.
    case_id = normalized_events[0].case_id
    if case_id is None:
        # If case_id is missing, we cannot create a finding (required field).
        # However, the Event schema requires case_id, so this should not happen.
        return []

    # Iterate over all unique pairs (i < j) to avoid self-correlation and duplicates.
    for i in range(len(normalized_events)):
        e1 = normalized_events[i]
        for j in range(i + 1, len(normalized_events)):
            e2 = normalized_events[j]

            # 1. Same-object correlation: both must have a non-None object and they must match.
            if e1.object is None or e2.object is None or e1.object != e2.object:
                continue

            # 2. Compute absolute time difference in minutes.
            time_diff = abs((e1.timestamp - e2.timestamp).total_seconds()) / 60.0

            # 3. Determine if this is an archive-upload pair.
            is_archive_upload_pair = (
                (e1.action == "archive_create" and e2.action == "file_upload") or
                (e1.action == "file_upload" and e2.action == "archive_create")
            )

            # 4. Select the appropriate time window.
            window_minutes = (
                archive_upload_window_minutes if is_archive_upload_pair
                else general_window_minutes
            )

            # 5. Check if within the selected window.
            if time_diff <= window_minutes:
                # 6. Build a correlation finding.
                # We need a rule_id that is deterministic for this type of correlation.
                # We'll use a string that reflects the rule: same-object and time window.
                # For archive-upload pairs we note the special window.
                if is_archive_upload_pair:
                    rule_id = "same_object_archive_upload_within_30m"
                else:
                    rule_id = "same_object_within_10m"

                claim = (
                    f"Two events refer to the same object ({e1.object!r}) "
                    f"and occurred within {int(window_minutes)} minutes."
                )
                reasoning = (
                    f"Event {e1.event_id} ({e1.source}:{e1.action}) and "
                    f"Event {e2.event_id} ({e2.source}:{e2.action}) both reference "
                    f"object {e1.object!r}. Their timestamps differ by {time_diff:.1f} minutes, "
                    f"which is within the {int(window_minutes)}-minute correlation window."
                )

                finding = common.make_finding(
                    case_id=case_id,
                    finding_type="correlation",
                    rule_id=rule_id,
                    claim=claim,
                    confidence=0.8,  # Placeholder deterministic confidence.
                    evidence_event_ids=[e1.event_id, e2.event_id],
                    reasoning=reasoning,
                    known_event_ids=common.extract_event_ids(events),
                    needs_human_review=True,
                )
                findings.append(finding)

    return findings