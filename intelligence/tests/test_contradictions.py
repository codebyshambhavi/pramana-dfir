import copy

from intelligence import common
from intelligence.contradictions import find_contradictions

CASE_ID = "CASE-TEST-001"


def event(event_id, timestamp, lat=None, lon=None, case_id=CASE_ID):
    event = {
        "event_id": event_id,
        "case_id": case_id,
        "evidence_id": "EVID-001",
        "artifact_ref": "synthetic.csv#row=1",
        "sha256": "a" * 64,
        "timestamp": timestamp,
        "source": "image",
        "action": "location_fix",
        "raw": {},
    }
    if lat is not None and lon is not None:
        event["location"] = {"lat": lat, "lon": lon}
    return event


def test_empty():
    assert find_contradictions([]) == []


def test_same_location_no_contradiction():
    events = [
        event("A", "2026-10-18T00:00:00Z", 28.6, 77.2),
        event("B", "2026-10-18T01:00:00Z", 28.6, 77.2),
    ]
    assert find_contradictions(events) == []


def test_plausible_distance_no_contradiction():
    events = [
        event("A", "2026-10-18T00:00:00Z", 28.6139, 77.2090),
        event("B", "2026-10-18T02:00:00Z", 28.7041, 77.1025),
    ]
    assert find_contradictions(events) == []


def test_impossible_travel_is_contradiction():
    events = [
        event("A", "2026-10-18T00:00:00Z", 28.6139, 77.2090),
        event("B", "2026-10-18T00:30:00Z", 19.0760, 72.8777),
    ]
    findings = find_contradictions(events)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["type"] == "contradiction"
    assert finding["evidence_event_ids"] == ["A", "B"]
    assert finding["needs_human_review"] is True
    common.validate_finding(finding)


def test_boundary_just_below_max_speed_is_not_contradiction():
    # About 889 km in one hour: below the configured 900 km/h threshold.
    events = [
        event("A", "2026-10-18T00:00:00Z", 0, 0),
        event("B", "2026-10-18T01:00:00Z", 8.0, 0),
    ]
    assert find_contradictions(events) == []


def test_zero_time_different_location_is_contradiction():
    events = [
        event("A", "2026-10-18T00:00:00Z", 0, 0),
        event("B", "2026-10-18T00:00:00Z", 10, 0),
    ]
    assert len(find_contradictions(events)) == 1


def test_missing_location_is_ignored():
    events = [
        event("A", "2026-10-18T00:00:00Z"),
        event("B", "2026-10-18T00:01:00Z", 10, 0),
    ]
    assert find_contradictions(events) == []


def test_different_cases_are_not_compared():
    events = [
        event("A", "2026-10-18T00:00:00Z", 0, 0),
        event("B", "2026-10-18T00:01:00Z", 10, 0, case_id="CASE-TEST-002"),
    ]
    assert find_contradictions(events) == []


def test_deterministic_regardless_of_input_order():
    events = [
        event("B", "2026-10-18T00:30:00Z", 19.0760, 72.8777),
        event("A", "2026-10-18T00:00:00Z", 28.6139, 77.2090),
    ]
    assert find_contradictions(events) == find_contradictions(list(reversed(events)))


def test_inputs_are_not_mutated():
    events = [
        event("A", "2026-10-18T00:00:00Z", 0, 0),
        event("B", "2026-10-18T00:30:00Z", 10, 0),
    ]
    snapshot = copy.deepcopy(events)
    find_contradictions(events)
    assert events == snapshot
