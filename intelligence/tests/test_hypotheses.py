import copy
import json

from jsonschema import Draft202012Validator

from intelligence import common
from intelligence.hypotheses import add_hypotheses

CASE_ID = "CASE-TEST-001"


def test_empty():
    assert add_hypotheses([]) == []


def test_anomaly_gets_three_alternatives():
    finding = {
        "finding_id": "F-1",
        "case_id": CASE_ID,
        "type": "anomaly",
        "claim": "Activity occurred during odd hours.",
        "confidence": 0.6,
        "evidence_event_ids": ["A"],
        "needs_human_review": True,
    }
    output = add_hypotheses([finding])[0]
    assert len(output["alternatives"]) == 3
    assert abs(sum(a["confidence"] for a in output["alternatives"]) - 1.0) < 1e-9


def test_contradiction_gets_three_alternatives():
    finding = {
        "finding_id": "F-1",
        "case_id": CASE_ID,
        "type": "contradiction",
        "claim": "Locations imply implausible travel.",
        "confidence": 0.95,
        "evidence_event_ids": ["A", "B"],
        "needs_human_review": True,
    }
    output = add_hypotheses([finding])[0]
    assert len(output["alternatives"]) == 3
    assert abs(sum(a["confidence"] for a in output["alternatives"]) - 1.0) < 1e-9


def test_alternatives_have_required_shape():
    finding = {
        "finding_id": "F-1",
        "case_id": CASE_ID,
        "type": "anomaly",
        "claim": "Activity occurred during odd hours.",
        "confidence": 0.6,
        "evidence_event_ids": ["A"],
        "needs_human_review": True,
    }
    output = add_hypotheses([finding])[0]
    for alternative in output["alternatives"]:
        assert isinstance(alternative["claim"], str)
        assert 0 <= alternative["confidence"] <= 1
        assert isinstance(alternative["needed_evidence"], list)


def test_other_finding_types_remain_unchanged():
    finding = {
        "finding_id": "F-1",
        "case_id": CASE_ID,
        "type": "correlation",
        "claim": "Two events are correlated.",
        "confidence": 0.6,
        "evidence_event_ids": ["A", "B"],
        "needs_human_review": True,
    }
    assert add_hypotheses([finding]) == [finding]


def test_input_is_not_mutated():
    finding = {
        "finding_id": "F-1",
        "case_id": CASE_ID,
        "type": "anomaly",
        "claim": "Activity occurred during odd hours.",
        "confidence": 0.6,
        "evidence_event_ids": ["A"],
        "needs_human_review": True,
    }
    snapshot = copy.deepcopy(finding)
    add_hypotheses([finding])
    assert finding == snapshot


def test_output_matches_frozen_finding_schema():
    schema = json.loads(
        common.FINDING_SCHEMA_PATH.read_text(encoding="utf-8")
    )
    finding = {
        "finding_id": "F-1",
        "case_id": CASE_ID,
        "type": "anomaly",
        "claim": "Activity occurred during odd hours.",
        "confidence": 0.6,
        "evidence_event_ids": ["A"],
        "needs_human_review": True,
    }
    output = add_hypotheses([finding])[0]
    Draft202012Validator(schema).validate(output)
