"""Tests for intelligence.common and intelligence.config (R2-1)."""
from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone

import pytest
from jsonschema import Draft202012Validator

from intelligence import common, config
from intelligence.tests import fixtures as fx

UTC_0230 = datetime(2026, 10, 18, 2, 30, 0)


def _finding(**kw):
    args = dict(
        case_id=fx.CASE_ID, finding_type="correlation", rule_id="rule-x",
        claim="Two events occurred close together.", confidence=0.6,
        evidence_event_ids=["EV-LOGIN", "EV-UPLOAD"], reasoning="Within window.",
        known_event_ids={"EV-LOGIN", "EV-UPLOAD", "EV-ARCHIVE"},
    )
    args.update(kw)
    return common.make_finding(**args)


# 1. timezone-aware timestamps
def test_aware_timestamp_normalizes_to_utc_naive():
    for text in ("2026-10-18T02:30:00Z", "2026-10-18T02:30:00+00:00", "2026-10-18T08:00:00+05:30"):
        parsed = common.parse_timestamp(text)
        assert parsed == UTC_0230 and parsed.tzinfo is None


def test_aware_datetime_object_normalizes():
    dt = datetime(2026, 10, 18, 8, 0, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    assert common.parse_timestamp(dt) == UTC_0230


# 2. naive timestamps are treated as UTC, not IST
def test_naive_timestamp_is_assumed_utc():
    parsed = common.parse_timestamp("2026-10-18T02:30:00")
    assert parsed == UTC_0230 and parsed.tzinfo is None
    assert parsed != UTC_0230 - timedelta(hours=5, minutes=30)


def test_naive_and_aware_fixtures_are_same_instant():
    assert (common.normalize_event(fx.naive_timestamp_event()).timestamp
            == common.normalize_event(fx.aware_timestamp_event()).timestamp)


@pytest.mark.parametrize("bad", ["", "   ", "not-a-time", "2026-13-45T00:00:00Z", None, 12345])
def test_invalid_timestamp_raises(bad):
    with pytest.raises(common.InvalidTimestampError):
        common.parse_timestamp(bad)


# 3. unordered sorting
def test_sort_unordered_events():
    evs = [fx.upload_event(), fx.login_event(), fx.location_event(), fx.archive_event()]
    assert [e["event_id"] for e in common.sort_events(evs)] == [
        "EV-LOGIN", "EV-ARCHIVE", "EV-UPLOAD", "EV-LOCATION"]


def test_sort_mixes_naive_and_aware_correctly():
    late_aware = fx.make_event("EV-A", "2026-10-18T09:00:00+05:30")  # 03:30 UTC
    early_naive = fx.make_event("EV-B", "2026-10-18T03:00:00")        # 03:00 UTC
    assert [e["event_id"] for e in common.sort_events([late_aware, early_naive])] == ["EV-B", "EV-A"]


# 4. deterministic tie-break
def test_sort_ties_broken_by_event_id_regardless_of_input_order():
    a, b, c = (fx.make_event(i, "2026-10-18T02:30:00Z") for i in ("EV-B", "EV-C", "EV-A"))
    expected = ["EV-A", "EV-B", "EV-C"]
    for order in ([a, b, c], [c, b, a], [b, a, c]):
        assert [e["event_id"] for e in common.sort_events(order)] == expected


def test_tie_break_treats_ids_as_opaque_strings():
    evs = [fx.make_event(i, "2026-10-18T02:30:00Z") for i in ("EV-10", "EV-9", "EV-2")]
    assert [e["event_id"] for e in common.sort_events(evs)] == ["EV-10", "EV-2", "EV-9"]


def test_normalize_events_sorted():
    out = common.normalize_events([fx.upload_event(), fx.login_event()])
    assert [n.event_id for n in out] == ["EV-LOGIN", "EV-UPLOAD"]


# 5. missing optional fields
def test_missing_optional_fields():
    n = common.normalize_event(fx.minimal_event())
    assert (n.device, n.actor, n.object, n.ip, n.location) == (None, None, None, None, None)
    assert n.raw == {}


def test_location_normalized_to_tuple():
    assert common.normalize_event(fx.location_event()).location == (12.9716, 77.5946)
    assert common.normalize_event(fx.make_event("E", "2026-10-18T00:00:00Z", location=None)).location is None


def test_event_without_id_or_timestamp_rejected():
    with pytest.raises(common.EventError):
        common.normalize_event({"timestamp": "2026-10-18T00:00:00Z"})
    with pytest.raises(common.EventError):
        common.normalize_event({"event_id": "EV-1"})


# event ID extraction
def test_event_id_extraction_is_opaque():
    evs = [fx.make_event("weird id/42", "2026-10-18T00:00:00Z"), fx.make_event("EV-7", "2026-10-18T00:00:01Z")]
    assert common.extract_event_ids(evs) == ["weird id/42", "EV-7"]
    assert common.event_id_set(evs) == {"weird id/42", "EV-7"}
    with pytest.raises(common.EventError):
        common.get_event_id({"event_id": 5})


# 6. deterministic finding IDs
def test_finding_id_same_input_same_id():
    assert _finding()["finding_id"] == _finding()["finding_id"]
    assert _finding()["finding_id"].startswith("F-")


def test_finding_id_independent_of_event_order_and_duplicates():
    a = _finding(evidence_event_ids=["EV-LOGIN", "EV-UPLOAD"])
    b = _finding(evidence_event_ids=["EV-UPLOAD", "EV-LOGIN", "EV-LOGIN"])
    assert a["finding_id"] == b["finding_id"]


def test_finding_id_differs_by_case():
    assert _finding()["finding_id"] != _finding(case_id=fx.OTHER_CASE_ID)["finding_id"]


def test_finding_id_differs_by_event_set():
    assert _finding()["finding_id"] != _finding(evidence_event_ids=["EV-LOGIN", "EV-ARCHIVE"])["finding_id"]


def test_finding_id_differs_by_type_and_rule():
    base = _finding()["finding_id"]
    assert base != _finding(finding_type="anomaly")["finding_id"]
    assert base != _finding(rule_id="rule-y")["finding_id"]


# 7. valid finding / 11. pending status
def test_made_finding_is_valid_and_pending():
    f = _finding()
    common.validate_finding(f)
    assert f["status"] == "pending"
    assert f["needs_human_review"] is True
    assert f["evidence_event_ids"] == ["EV-LOGIN", "EV-UPLOAD"]


def test_finding_with_alternatives_valid():
    f = _finding(alternatives=[{"claim": "Coincidence", "confidence": 0.3, "needed_evidence": ["more logs"]}])
    common.validate_finding(f)


def test_validation_uses_real_schema_file():
    schema = json.loads(common.FINDING_SCHEMA_PATH.read_text(encoding="utf-8"))
    assert common.FINDING_SCHEMA_PATH.name == "finding.schema.json"
    Draft202012Validator(schema).validate(_finding())


# 8. invalid finding rejection
@pytest.mark.parametrize("mutate", [
    lambda f: f.pop("claim"),
    lambda f: f.update(confidence=1.5),
    lambda f: f.update(confidence=-0.1),
    lambda f: f.update(confidence=float("nan")),
    lambda f: f.update(type="verdict"),
    lambda f: f.update(evidence_event_ids=[]),
    lambda f: f.update(status="maybe"),
    lambda f: f.update(invented_field=1),
    lambda f: f.update(needs_human_review="yes"),
])
def test_invalid_finding_rejected(mutate):
    f = _finding()
    mutate(f)
    with pytest.raises(common.FindingValidationError):
        common.validate_finding(f)


def test_make_finding_rejects_invalid_inputs():
    with pytest.raises(common.FindingValidationError):
        _finding(confidence=2)
    with pytest.raises(common.FindingValidationError):
        _finding(finding_type="not-a-type")
    with pytest.raises(common.FindingValidationError):
        _finding(evidence_event_ids=[], known_event_ids=set())


# 9. valid event-id references
def test_known_event_ids_accepted(known_ids):
    f = _finding(evidence_event_ids=["EV-LOGIN"], known_event_ids=known_ids)
    common.check_event_ids_known(f, known_ids)


# 10. unknown event-id rejection (no silent removal)
def test_unknown_event_id_rejected_not_dropped():
    with pytest.raises(common.UnknownEventIdError, match="EV-GHOST"):
        _finding(evidence_event_ids=["EV-LOGIN", "EV-GHOST"])


def test_check_event_ids_known_on_existing_finding():
    f = _finding()
    with pytest.raises(common.UnknownEventIdError):
        common.check_event_ids_known(f, {"EV-LOGIN"})
    assert f["evidence_event_ids"] == ["EV-LOGIN", "EV-UPLOAD"]  # untouched


# 12. no mutation of inputs
def test_inputs_not_mutated(events):
    snapshot = copy.deepcopy(events)
    events[0]["raw"] = {"nested": {"k": [1, 2]}}
    snapshot[0]["raw"] = {"nested": {"k": [1, 2]}}
    common.sort_events(events)
    common.normalize_events(events)
    common.extract_event_ids(events)
    n = common.normalize_event(events[0])
    n.raw["nested"]["k"].append(99)  # mutate the normalized copy
    assert events == snapshot


def test_make_finding_does_not_mutate_inputs():
    ids, alts = ["EV-UPLOAD", "EV-LOGIN"], [{"claim": "x", "confidence": 0.1}]
    ids_c, alts_c = list(ids), copy.deepcopy(alts)
    f = _finding(evidence_event_ids=ids, alternatives=alts)
    f["alternatives"][0]["claim"] = "changed"
    assert ids == ids_c and alts == alts_c


# fixtures conform to the real Event schema
def test_all_fixtures_validate_against_event_schema(events):
    schema = json.loads((common.CONTRACTS_DIR / "event.schema.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    for e in events:
        validator.validate(e)


# config
def test_default_timezone_is_utc(monkeypatch):
    monkeypatch.delenv(config.TIMEZONE_ENV_VAR, raising=False)
    assert config.get_timezone() is timezone.utc


def test_timezone_configurable(monkeypatch):
    monkeypatch.setenv(config.TIMEZONE_ENV_VAR, "Asia/Kolkata")
    try:
        tz = config.get_timezone()
    except ValueError:
        pytest.skip("tz database unavailable")
    assert datetime(2026, 10, 18, 2, 30, tzinfo=timezone.utc).astimezone(tz).hour == 8


def test_invalid_timezone_rejected(monkeypatch):
    monkeypatch.setenv(config.TIMEZONE_ENV_VAR, "Mars/Olympus")
    with pytest.raises(ValueError):
        config.get_timezone()


def test_config_windows_are_positive():
    assert config.DEFAULT_CORRELATION_WINDOW > timedelta(0)
    assert config.ARCHIVE_UPLOAD_WINDOW > timedelta(0)
    assert 0 <= config.ODD_HOUR_START < 24 and 0 <= config.ODD_HOUR_END < 24
