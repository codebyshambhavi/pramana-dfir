"""Stage 0 / T2: time model (case timezone, source clocks, intervals, ordering)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from intelligence import common, config
from intelligence.timeline import (
    SourceClock,
    TimeInterval,
    effective_interval,
    event_interval,
    load_source_clocks,
    parse_source_clocks,
    sort_by_interval,
    to_case_time,
    tz_label,
)
from intelligence.tests.fixtures import make_event

T = datetime(2026, 10, 18, 10, 0, 0)
MIN = timedelta(minutes=1)


def iv(lo_min: float, hi_min: float) -> TimeInterval:
    return TimeInterval(T + lo_min * MIN, T + hi_min * MIN)


# ---- IST / case timezone ----------------------------------------------------
def test_ist_conversion_is_plus_0530(monkeypatch):
    monkeypatch.setenv(config.TIMEZONE_ENV_VAR, "Asia/Kolkata")
    tz = config.get_timezone()
    local = to_case_time(datetime(2026, 10, 18, 2, 17, 0), tz)
    assert (local.hour, local.minute) == (7, 47)
    assert local.utcoffset() == timedelta(hours=5, minutes=30)
    assert tz_label(tz) == "Asia/Kolkata"


def test_ist_date_rolls_over_across_midnight():
    tz = ZoneInfo("Asia/Kolkata")
    local = to_case_time(datetime(2026, 10, 18, 19, 0, 0), tz)  # 19:00Z = 00:30 next day IST
    assert (local.day, local.hour, local.minute) == (19, 0, 30)


def test_utc_label_and_conversion_is_identity():
    assert tz_label(timezone.utc) == "UTC"
    assert to_case_time(T, timezone.utc).hour == 10


def test_conversion_never_changes_the_input():
    original = datetime(2026, 10, 18, 2, 17, 0)
    to_case_time(original, timezone.utc)
    assert original == datetime(2026, 10, 18, 2, 17, 0) and original.tzinfo is None


# ---- source offset + uncertainty -> interval --------------------------------
def test_no_clock_means_a_point_interval():
    i = effective_interval(T)
    assert i.lo == i.hi == T


def test_positive_offset_means_source_ran_ahead():
    # recorded 10:00 by a clock 4 min ahead => true time 09:56
    i = effective_interval(T, SourceClock(offset=4 * MIN))
    assert i.lo == i.hi == T - 4 * MIN


def test_negative_offset_means_source_ran_behind():
    i = effective_interval(T, SourceClock(offset=-3 * MIN))
    assert i.lo == i.hi == T + 3 * MIN


def test_offset_and_uncertainty_example_from_spec():
    i = effective_interval(T, SourceClock(offset=4 * MIN, uncertainty=2 * MIN))
    assert i.lo == T - 6 * MIN and i.hi == T - 2 * MIN
    assert i.midpoint == T - 4 * MIN


def test_negative_uncertainty_rejected():
    with pytest.raises(ValueError):
        SourceClock(uncertainty=-1 * MIN)


def test_inverted_interval_rejected():
    with pytest.raises(ValueError):
        TimeInterval(T + MIN, T)


def test_event_interval_uses_the_clock_of_the_events_source_and_keeps_raw():
    ev = make_event("E1", "2026-10-18T10:00:00Z", source="log")
    n = common.normalize_event(ev)
    clocks = {"log": SourceClock(offset=4 * MIN, uncertainty=2 * MIN)}
    assert event_interval(n, clocks) == TimeInterval(T - 6 * MIN, T - 2 * MIN)
    other = common.normalize_event(make_event("E2", "2026-10-18T10:00:00Z", source="chat"))
    assert event_interval(other, clocks).lo == T          # no clock for 'chat'
    assert ev["timestamp"] == "2026-10-18T10:00:00Z"      # raw untouched
    assert n.timestamp == T


# ---- definitely vs possibly before -----------------------------------------
def test_clearly_separated_is_definitely_before():
    a, b = iv(0, 1), iv(5, 6)
    assert a.definitely_before(b) and a.possibly_before(b)
    assert not b.definitely_before(a) and not b.possibly_before(a)
    assert b.definitely_after(a) and b.possibly_after(a)


def test_overlapping_is_possible_both_ways_never_definite():
    a, b = iv(0, 5), iv(3, 8)
    assert a.overlaps(b)
    assert not a.definitely_before(b) and not b.definitely_before(a)
    assert a.possibly_before(b) and b.possibly_before(a)


def test_equal_boundary_is_not_definite():
    a, b = iv(0, 2), iv(2, 4)          # a.hi == b.lo
    assert not a.definitely_before(b)  # strict: touching is ambiguous
    assert a.possibly_before(b)
    assert a.overlaps(b)


def test_identical_instants_are_neither_definitely_nor_possibly_before():
    a, b = iv(1, 1), iv(1, 1)
    assert not a.definitely_before(b) and not b.definitely_before(a)
    assert not a.possibly_before(b) and not b.possibly_before(a)


def test_contained_interval_is_possible_both_ways():
    a, b = iv(0, 10), iv(4, 5)
    assert a.possibly_before(b) and b.possibly_before(a)
    assert not a.definitely_before(b) and not b.definitely_before(a)


def test_uncertainty_turns_a_definite_order_into_a_possible_one():
    # Raw order: A 10:00, B 10:03 -> with exact clocks A is definitely before B.
    a = effective_interval(T)
    b = effective_interval(T + 3 * MIN)
    assert a.definitely_before(b)
    # Give both sources +-2 min uncertainty: A=[9:58,10:02], B=[10:01,10:05] overlap.
    clock = SourceClock(uncertainty=2 * MIN)
    a, b = effective_interval(T, clock), effective_interval(T + 3 * MIN, clock)
    assert not a.definitely_before(b)
    assert a.possibly_before(b) and b.possibly_before(a)


def test_source_offset_can_reverse_the_apparent_order():
    # Raw: log says 10:00, browser says 10:02. Log clock is 5 min AHEAD
    # => true log time 09:55, still before; browser clock 5 min ahead => 09:57.
    # But if the BROWSER is 5 min ahead and the log is exact, browser true = 09:57 < log 10:00.
    log = effective_interval(T)
    browser = effective_interval(T + 2 * MIN, SourceClock(offset=5 * MIN))
    assert browser.definitely_before(log)
    assert not log.possibly_before(browser)


def test_definitely_implies_possibly():
    for a in (iv(0, 1), iv(0, 3), iv(2, 2)):
        for b in (iv(0, 1), iv(2, 3), iv(4, 9)):
            if a.definitely_before(b):
                assert a.possibly_before(b)


# ---- deterministic ordering --------------------------------------------------
def test_sort_by_interval_is_input_order_independent_and_breaks_ties_by_id():
    evs = [
        make_event("B", "2026-10-18T10:00:00Z"),
        make_event("A", "2026-10-18T10:00:00Z"),
        make_event("C", "2026-10-18T09:59:00Z"),
    ]
    normalized = [common.normalize_event(e) for e in evs]
    order = [e.event_id for e in sort_by_interval(normalized)]
    assert order == ["C", "A", "B"]
    assert [e.event_id for e in sort_by_interval(list(reversed(normalized)))] == order


def test_sort_by_interval_uses_offset_corrected_times():
    log = common.normalize_event(make_event("LOG", "2026-10-18T10:00:00Z", source="log"))
    web = common.normalize_event(make_event("WEB", "2026-10-18T10:02:00Z", source="browser"))
    assert [e.event_id for e in sort_by_interval([log, web])] == ["LOG", "WEB"]
    clocks = {"browser": SourceClock(offset=5 * MIN)}     # browser really 09:57
    assert [e.event_id for e in sort_by_interval([log, web], clocks)] == ["WEB", "LOG"]


def test_wider_interval_sorts_after_narrower_with_same_lo():
    a = common.normalize_event(make_event("A", "2026-10-18T10:02:00Z", source="log"))
    b = common.normalize_event(make_event("B", "2026-10-18T10:00:00Z", source="chat"))
    clocks = {"log": SourceClock(uncertainty=2 * MIN)}    # A = [10:00, 10:04]; B = [10:00,10:00]
    assert [e.event_id for e in sort_by_interval([a, b], clocks)] == ["B", "A"]


# ---- configuration -----------------------------------------------------------
def test_load_source_clocks_from_env(monkeypatch):
    monkeypatch.setenv(config.SOURCE_CLOCKS_ENV_VAR, '{"log": {"offset_seconds": 240, "uncertainty_seconds": 120}}')
    clocks = load_source_clocks()
    assert clocks == {"log": SourceClock(offset=4 * MIN, uncertainty=2 * MIN)}


def test_unset_or_blank_env_means_no_clocks(monkeypatch):
    monkeypatch.delenv(config.SOURCE_CLOCKS_ENV_VAR, raising=False)
    assert load_source_clocks() == {}
    monkeypatch.setenv(config.SOURCE_CLOCKS_ENV_VAR, "  ")
    assert load_source_clocks() == {}


@pytest.mark.parametrize(
    "bad",
    [
        "not json",
        "[1, 2]",
        '{"printer": {"offset_seconds": 1}}',                    # unknown source
        '{"log": {"offset_minutes": 4}}',                        # unknown key
        '{"log": {"offset_seconds": "4"}}',                      # not a number
        '{"log": {"offset_seconds": true}}',
        '{"log": {"uncertainty_seconds": -5}}',                  # negative uncertainty
        '{"log": 4}',
    ],
)
def test_invalid_source_clock_config_is_an_error(monkeypatch, bad):
    monkeypatch.setenv(config.SOURCE_CLOCKS_ENV_VAR, bad)
    with pytest.raises(ValueError):
        load_source_clocks()


def test_parse_source_clocks_defaults_missing_keys_to_zero():
    assert parse_source_clocks({"chat": {"offset_seconds": 60}}) == {"chat": SourceClock(offset=MIN)}
