"""Time foundations for Role 2 (Stage 0 / T2).

Three small, deterministic pieces. Nothing here rewrites or stores timestamps:
the raw Event ``timestamp`` is always left untouched, and everything below is
*derived* when an Event is interpreted.

1. Case timezone
   Wall-clock rules (e.g. odd hours) are evaluated in the configured case
   timezone (``config.get_timezone()``), by converting the UTC instant with
   ``to_case_time``. Naive Event timestamps keep meaning UTC (see ``common``).

2. Source clock model
   A ``SourceClock`` says how a source's clock relates to true case time:
   ``offset``      - how far the source clock reads AHEAD of true time
                     (+4 min: a recorded 10:04 really happened at 10:00;
                     negative = the source runs behind),
   ``uncertainty`` - symmetric +/- error that remains after the offset.
   Clocks are configured per Event ``source`` (browser, chat, log, pcap, image)
   through the ``PRAMANA_SOURCE_CLOCKS`` environment variable, e.g.
   ``{"log": {"offset_seconds": 240, "uncertainty_seconds": 120}}``.
   A source with no entry has offset 0 and uncertainty 0, so its interval is a
   single instant and behaviour equals the pre-T2 behaviour.

3. Intervals and ordering
   ``effective_interval`` turns ``raw timestamp + offset + uncertainty`` into
   ``TimeInterval[lo, hi]`` (UTC-naive). Ordering is three-valued on purpose:
   ``definitely_before`` (A.hi < B.lo) is the only claim that may be made as
   fact; ``possibly_before`` (A.lo < B.hi) means the intervals do not rule it
   out. Equal boundaries are NOT definite. ``sort_by_interval`` is a total,
   input-order-independent ordering (lo, hi, event_id) for display only; it
   never asserts that adjacent items are definitely ordered.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any, Iterable, Mapping

from .common import NormalizedEvent
from .config import SOURCE_CLOCKS_ENV_VAR

KNOWN_SOURCES = frozenset({"browser", "chat", "log", "pcap", "image"})
_ZERO = timedelta(0)


@dataclass(frozen=True)
class SourceClock:
    """How one source's clock relates to true case time (see module docstring)."""

    offset: timedelta = _ZERO
    uncertainty: timedelta = _ZERO

    def __post_init__(self) -> None:
        if self.uncertainty < _ZERO:
            raise ValueError("SourceClock.uncertainty must not be negative")


NO_CLOCK_ERROR = SourceClock()


@dataclass(frozen=True)
class TimeInterval:
    """Closed interval [lo, hi] of possible true times, UTC-naive."""

    lo: datetime
    hi: datetime

    def __post_init__(self) -> None:
        if self.lo > self.hi:
            raise ValueError(f"TimeInterval lo {self.lo} is after hi {self.hi}")

    @property
    def midpoint(self) -> datetime:
        return self.lo + (self.hi - self.lo) / 2

    def definitely_before(self, other: "TimeInterval") -> bool:
        """True only if EVERY possible time of self precedes EVERY possible time of other."""
        return self.hi < other.lo

    def possibly_before(self, other: "TimeInterval") -> bool:
        """True unless the intervals rule out self happening before other."""
        return self.lo < other.hi

    def definitely_after(self, other: "TimeInterval") -> bool:
        return other.definitely_before(self)

    def possibly_after(self, other: "TimeInterval") -> bool:
        return other.possibly_before(self)

    def overlaps(self, other: "TimeInterval") -> bool:
        return self.lo <= other.hi and other.lo <= self.hi


def effective_interval(raw_utc: datetime, clock: SourceClock | None = None) -> TimeInterval:
    """``raw timestamp`` -> subtract source offset -> widen by uncertainty."""
    clock = clock or NO_CLOCK_ERROR
    centre = raw_utc - clock.offset
    return TimeInterval(centre - clock.uncertainty, centre + clock.uncertainty)


def event_interval(
    event: NormalizedEvent, clocks: Mapping[str, SourceClock] | None = None
) -> TimeInterval:
    """Effective interval of an Event using the clock configured for its source."""
    clock = (clocks or {}).get(event.source or "")
    return effective_interval(event.timestamp, clock)


def sort_by_interval(
    events: Iterable[NormalizedEvent], clocks: Mapping[str, SourceClock] | None = None
) -> list[NormalizedEvent]:
    """Deterministic total order by (lo, hi, event_id); independent of input order."""
    keyed = [(event_interval(e, clocks), e) for e in events]
    keyed.sort(key=lambda pair: (pair[0].lo, pair[0].hi, pair[1].event_id))
    return [event for _, event in keyed]


# --- case timezone ----------------------------------------------------------
def to_case_time(utc_naive: datetime, case_tz: tzinfo) -> datetime:
    """Interpret a UTC-naive instant as wall-clock time in the case timezone."""
    return utc_naive.replace(tzinfo=timezone.utc).astimezone(case_tz)


def tz_label(case_tz: tzinfo) -> str:
    """Human-readable name of a timezone (IANA key when it has one)."""
    return getattr(case_tz, "key", None) or ("UTC" if case_tz is timezone.utc else str(case_tz))


# --- configuration ----------------------------------------------------------
def parse_source_clocks(spec: Any) -> dict[str, SourceClock]:
    """Validate a ``{source: {offset_seconds, uncertainty_seconds}}`` mapping."""
    if not isinstance(spec, dict):
        raise ValueError("source clocks must be a JSON object keyed by source")
    clocks: dict[str, SourceClock] = {}
    for source, entry in spec.items():
        if source not in KNOWN_SOURCES:
            raise ValueError(f"unknown source {source!r}; expected one of {sorted(KNOWN_SOURCES)}")
        if not isinstance(entry, dict) or not set(entry) <= {"offset_seconds", "uncertainty_seconds"}:
            raise ValueError(f"source clock for {source!r} must only contain offset_seconds and uncertainty_seconds")
        values = {}
        for key in ("offset_seconds", "uncertainty_seconds"):
            value = entry.get(key, 0)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or abs(value) == float("inf"):
                raise ValueError(f"source clock {source!r}.{key} must be a finite number")
            values[key] = value
        clocks[source] = SourceClock(
            offset=timedelta(seconds=values["offset_seconds"]),
            uncertainty=timedelta(seconds=values["uncertainty_seconds"]),
        )
    return clocks


def load_source_clocks(environ: Mapping[str, str] | None = None) -> dict[str, SourceClock]:
    """Read source clocks from ``PRAMANA_SOURCE_CLOCKS`` (empty/unset -> none)."""
    text = (environ if environ is not None else os.environ).get(SOURCE_CLOCKS_ENV_VAR, "").strip()
    if not text:
        return {}
    try:
        spec = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{SOURCE_CLOCKS_ENV_VAR} is not valid JSON: {exc}") from exc
    return parse_source_clocks(spec)
