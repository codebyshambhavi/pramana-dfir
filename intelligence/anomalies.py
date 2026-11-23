"""Role 2: rule-based anomalies.

Implemented rule: ``odd_hour_activity``.

Semantics (Stage 0 / T2):

* Only login/session-type Events are candidates (``config.ODD_HOUR_ACTIONS``,
  matched case-insensitively on ``Event.action``). Chat, image, DNS, archive,
  upload and every other action are never flagged by this rule.
* "Odd hour" is wall-clock time in the CONFIGURED CASE TIMEZONE
  (``config.get_timezone()``), not the UTC hour. The Event's raw timestamp is
  never modified; it is converted only for this comparison.
* If a source clock is configured for the Event's source
  (``timeline.load_source_clocks``) the true-time interval is
  ``[raw - offset - uncertainty, raw - offset + uncertainty]``. When the whole
  interval is inside the odd-hour window the finding is emitted normally; when
  only part of it is, the finding is still emitted but at lower confidence and
  says so, because the clock uncertainty makes the rule's outcome ambiguous.
"""

from __future__ import annotations

from datetime import tzinfo
from typing import Any, Mapping

from . import common
from .config import ODD_HOUR_ACTIONS, ODD_HOUR_END, ODD_HOUR_START, get_timezone
from .timeline import (
    SourceClock,
    TimeInterval,
    event_interval,
    load_source_clocks,
    to_case_time,
    tz_label,
)

_CONFIDENCE_CERTAIN = 0.7
_CONFIDENCE_BOUNDARY = 0.4


def _is_odd_hour(hour: int) -> bool:
    """ODD_HOUR_START/END are a half-open local-hour range; start > end wraps midnight."""
    if ODD_HOUR_START < ODD_HOUR_END:
        return ODD_HOUR_START <= hour < ODD_HOUR_END
    return hour >= ODD_HOUR_START or hour < ODD_HOUR_END


def _odd_status(interval: TimeInterval, case_tz: tzinfo) -> str:
    """'all', 'some' or 'none' of the interval's end/mid points fall in odd hours."""
    points = (interval.lo, interval.midpoint, interval.hi)
    odd = [_is_odd_hour(to_case_time(p, case_tz).hour) for p in points]
    if all(odd):
        return "all"
    return "some" if any(odd) else "none"


def find_anomalies(
    events: list[dict[str, Any]],
    *,
    case_timezone: tzinfo | None = None,
    source_clocks: Mapping[str, SourceClock] | None = None,
) -> list[dict[str, Any]]:
    """Return anomaly Findings for login/session Events during local odd hours.

    Args:
        events: Event dictionaries (contracts/event.schema.json).
        case_timezone: overrides the configured case timezone (default: config).
        source_clocks: overrides the configured source clocks (default: env).

    Returns:
        Finding dictionaries (contracts/finding.schema.json) with type="anomaly".
    """
    if not events:
        return []

    case_tz = case_timezone if case_timezone is not None else get_timezone()
    clocks = source_clocks if source_clocks is not None else load_source_clocks()
    zone = tz_label(case_tz)
    window = f"[{ODD_HOUR_START:02d}:00, {ODD_HOUR_END:02d}:00)"

    normalized_events = common.normalize_events(events)
    known_event_ids = common.extract_event_ids(events)

    findings: list[dict[str, Any]] = []

    for event in normalized_events:
        if (event.action or "").strip().lower() not in ODD_HOUR_ACTIONS:
            continue

        interval = event_interval(event, clocks)
        status = _odd_status(interval, case_tz)
        if status == "none":
            continue

        local = to_case_time(interval.midpoint, case_tz)
        raw_local = to_case_time(event.timestamp, case_tz)
        clock = clocks.get(event.source or "")
        clock_note = ""
        if clock is not None and (clock.offset or clock.uncertainty):
            clock_note = (
                f" Source clock for '{event.source}': offset {clock.offset.total_seconds():+.0f}s, "
                f"uncertainty ±{clock.uncertainty.total_seconds():.0f}s, so the true time lies in "
                f"[{to_case_time(interval.lo, case_tz).isoformat()}, "
                f"{to_case_time(interval.hi, case_tz).isoformat()}]."
            )

        if status == "all":
            claim = (
                f"{event.action} event at {local:%H:%M} {zone} (case local time) falls within "
                f"the configured odd hours window {window} {zone}."
            )
            confidence = _CONFIDENCE_CERTAIN
        else:
            claim = (
                f"{event.action} event may fall within the configured odd hours window "
                f"{window} {zone}; clock uncertainty straddles the window boundary."
            )
            confidence = _CONFIDENCE_BOUNDARY

        reasoning = (
            f"A {event.action or 'login/session'} activity from {event.source or 'an unknown source'} "
            f"was recorded at {event.timestamp.isoformat()} UTC, which is "
            f"{raw_local:%Y-%m-%d %H:%M:%S} {zone} local time. The odd-hours "
            f"rule applies only to login/session events and is evaluated in "
            f"the case timezone ({zone}), window {window}.{clock_note}"
        )

        findings.append(
            common.make_finding(
                case_id=event.case_id or "",
                finding_type="anomaly",
                rule_id="odd_hour_activity",
                claim=claim,
                confidence=confidence,
                evidence_event_ids=[event.event_id],
                reasoning=reasoning,
                known_event_ids=known_event_ids,
                needs_human_review=True,
            )
        )

    return findings
