from __future__ import annotations

import copy

import pytest

from intelligence.authenticity import score_image
from intelligence.common import validate_finding


def make_event(event_id="EV-IMG-1", *, case_id="CASE-001", sha256="a" * 64,
               artifact_ref="photo.jpg#exif", evidence_id="EVID-001", location=None,
               source="image"):
    event = {
        "event_id": event_id, "case_id": case_id, "evidence_id": evidence_id,
        "artifact_ref": artifact_ref, "sha256": sha256,
        "timestamp": "2026-10-18T10:00:00Z", "source": source,
        "action": "image_metadata",
    }
    if location is not None:
        event["location"] = location
    return event


def statuses(result):
    return {s["name"]: s["status"] for s in result["signals"]}


def test_single_image_returns_required_signals_and_finding():
    result = score_image([make_event()])
    assert result["rating"] in {"low", "medium", "high"}
    assert {s["name"] for s in result["signals"]} == {
        "hash_consistency", "metadata_consistency", "perceptual_match", "provenance"
    }
    validate_finding(result["finding"])
    assert result["finding"]["type"] == "hypothesis"
    assert result["finding"]["evidence_event_ids"] == ["EV-IMG-1"]


def test_single_image_is_medium_when_comparison_signals_are_unavailable():
    result = score_image([make_event()])
    assert result["rating"] == "medium"
    assert statuses(result)["hash_consistency"] == "pass"
    assert statuses(result)["metadata_consistency"] == "unavailable"
    assert statuses(result)["perceptual_match"] == "unavailable"
    assert statuses(result)["provenance"] == "pass"


def test_repeated_reference_with_same_hash_and_location_is_consistent():
    events = [
        make_event("EV-1", location={"lat": 28.6139, "lon": 77.2090}),
        make_event("EV-2", location={"lat": 28.6139, "lon": 77.2090}),
    ]
    result = score_image(events)
    assert statuses(result)["hash_consistency"] == "pass"
    assert statuses(result)["metadata_consistency"] == "pass"


def test_repeated_reference_with_different_hash_is_conflict():
    result = score_image([make_event("EV-1"), make_event("EV-2", sha256="b" * 64)])
    assert statuses(result)["hash_consistency"] == "conflict"
    assert result["rating"] == "medium"


def test_repeated_reference_with_conflicting_location_is_conflict():
    events = [
        make_event("EV-1", location={"lat": 28.6139, "lon": 77.2090}),
        make_event("EV-2", location={"lat": 19.0760, "lon": 72.8777}),
    ]
    result = score_image(events)
    assert statuses(result)["metadata_consistency"] == "conflict"
    assert result["rating"] == "medium"


def test_missing_provenance_is_conflict():
    result = score_image([make_event(artifact_ref="")])
    assert statuses(result)["provenance"] == "conflict"
    assert result["rating"] == "medium"


def test_invalid_hash_is_a_conflict():
    result = score_image([make_event(sha256="not-a-sha")])
    assert statuses(result)["hash_consistency"] == "conflict"


def test_non_image_events_are_ignored_and_not_cited():
    result = score_image([make_event("EV-BROWSER", source="browser"), make_event("EV-IMG")])
    assert result["finding"]["evidence_event_ids"] == ["EV-IMG"]


def test_no_image_events_raise():
    with pytest.raises(ValueError, match="at least one image Event"):
        score_image([make_event(source="browser")])


def test_deterministic_and_input_not_mutated():
    events = [make_event("EV-2"), make_event("EV-1")]
    before = copy.deepcopy(events)
    assert score_image(events) == score_image(events)
    assert events == before


def test_result_never_uses_the_word_fake():
    assert "fake" not in str(score_image([make_event()])).lower()
