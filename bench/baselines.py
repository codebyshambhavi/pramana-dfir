"""Deterministic event-link baselines for controlled benchmark comparisons."""
from __future__ import annotations

from datetime import datetime
from itertools import combinations
from typing import Any


def _time(event: dict[str, Any]) -> datetime:
    value = str(event["timestamp"])
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _shared_identifier(first: dict[str, Any], second: dict[str, Any]) -> bool:
    for field in ("actor", "device", "ip", "object"):
        left, right = first.get(field), second.get(field)
        if not isinstance(left, str) or not isinstance(right, str):
            continue
        left_value, right_value = left.strip().casefold(), right.strip().casefold()
        if left_value and left_value == right_value:
            return True
    return False


def correlate_time_window(
    events: list[dict[str, Any]],
    *,
    window_minutes: float = 15,
    require_shared_identifier: bool = False,
) -> list[tuple[str, str]]:
    """Return cross-source event pairs within a time window.

    B1 uses temporal proximity alone. B2 additionally requires an exactly shared
    actor, device, IP address, or object value.
    """
    if window_minutes < 0:
        raise ValueError("window_minutes must be non-negative")
    ordered = sorted(events, key=lambda event: (_time(event), str(event["event_id"])))
    links: set[tuple[str, str]] = set()
    for first, second in combinations(ordered, 2):
        delta = (_time(second) - _time(first)).total_seconds() / 60
        if delta > window_minutes:
            continue
        if first.get("evidence_id") == second.get("evidence_id"):
            continue
        if require_shared_identifier and not _shared_identifier(first, second):
            continue
        refs = tuple(sorted((str(first["artifact_ref"]), str(second["artifact_ref"]))))
        if refs[0] != refs[1]:
            links.add(refs)
    return sorted(links)


def time_window_only(events: list[dict[str, Any]], *, window_minutes: float = 15) -> dict[str, Any]:
    """B1: correlate any cross-source events near each other in time."""
    return {
        "links": correlate_time_window(events, window_minutes=window_minutes),
        "method": "time_window_only",
        "window_minutes": window_minutes,
    }


def time_window_shared_identifier(
    events: list[dict[str, Any]],
    *,
    window_minutes: float = 15,
) -> dict[str, Any]:
    """B2: correlate near-time cross-source events sharing a simple identifier."""
    return {
        "links": correlate_time_window(
            events,
            window_minutes=window_minutes,
            require_shared_identifier=True,
        ),
        "method": "time_window_shared_identifier",
        "window_minutes": window_minutes,
    }
