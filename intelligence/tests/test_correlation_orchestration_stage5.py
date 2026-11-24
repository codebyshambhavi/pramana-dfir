from __future__ import annotations

import copy

import pytest

from intelligence.correlation import (
    CorrelationInputError,
    correlate_relationships,
    load_registry,
)

REGISTRY = load_registry()


def ev(key, **updates):
    value = {
        "event_id": key,
        "case_id": "case-a",
        "evidence_id": f"evidence-{key}",
        "artifact_ref": f"artifact-{key}",
        "source": "log",
        "timestamp": "2026-11-24T10:00:00Z",
        "action": "login",
        "actor": "alice@example.org",
        "integrity_status": "MATCH",
        "parser_confidence": 1.0,
        "acquisition_method": "vendor_export",
        "raw": {},
    }
    value.update(updates)
    return value


def test_orchestrator_emits_primary_for_valid_sha256_and_does_not_duplicate_secondary():
    digest = "a" * 64
    a = ev("a", source="gmail", raw={"attachments": [{"filename": "x.pdf", "sha256": digest}]})
    b = ev("b", source="log", object=digest)
    result = correlate_relationships([a, b], REGISTRY)
    assert result.relationship_count == 1
    rel = result.relationships[0]
    assert rel["relationship_type"] == "PRIMARY"
    assert rel["status"] == "VALIDATED_DIRECT"
    assert rel["case_id"] == "case-a"
    assert rel["relationship_id"].startswith("rel_")
    assert len(rel["relationship_id"]) == 68
    assert rel["evidence_pointers"]["source"]["evidence_id"]
    assert "Primary relationship" in rel["explanation"]


def test_orchestrator_emits_secondary_with_explanation_and_registry_provenance():
    a = ev("a", source="log", account_id="account-7")
    b = ev("b", source="log", account_id="account-7", timestamp="2026-11-24T10:02:00Z")
    result = correlate_relationships([a, b], REGISTRY)
    assert result.relationship_count == 1
    rel = result.relationships[0]
    assert rel["relationship_type"] == "SECONDARY"
    assert rel["status"] in {"ANALYST_REVIEW", "HIGH_CONFIDENCE"}
    assert rel["score"] >= REGISTRY.t_review
    assert rel["feature_contributions"]
    assert rel["registry_hash"] == REGISTRY.registry_hash
    assert rel["registry_version"] == REGISTRY.registry_version
    assert rel["config_version"] == REGISTRY.config_version
    assert rel["thresholds"]["status"] == "PROVISIONAL"
    assert "Secondary score" in rel["explanation"]


def test_orchestrator_is_deterministic_and_input_order_independent():
    a = ev("a", source="log", account_id="account-7")
    b = ev("b", source="log", account_id="account-7", timestamp="2026-11-24T10:02:00Z")
    first = correlate_relationships([a, b], REGISTRY).to_dict()
    second = correlate_relationships([copy.deepcopy(b), copy.deepcopy(a)], REGISTRY).to_dict()
    assert first == second


def test_mixed_cases_never_produce_cross_case_relationships():
    digest = "b" * 64
    a = ev("a", source="gmail", raw={"attachments": [{"filename": "x.pdf", "sha256": digest}]})
    b = ev("b", source="log", object=digest, case_id="case-b")
    c = ev("c", source="log", object=digest, case_id="case-a")
    result = correlate_relationships([a, b, c], REGISTRY)
    assert all(r["case_id"] == "case-a" for r in result.relationships)
    assert all(r["source_event_id"] != "b" and r["target_event_id"] != "b" for r in result.relationships)


def test_missing_case_or_event_id_is_rejected():
    with pytest.raises(CorrelationInputError, match="case_id"):
        correlate_relationships([ev("a", case_id=None)], REGISTRY)
    with pytest.raises(CorrelationInputError, match="event_id"):
        correlate_relationships([ev("missing", event_id=None)], REGISTRY)


def test_duplicate_event_id_within_case_is_rejected():
    with pytest.raises(CorrelationInputError, match="duplicate event_id"):
        correlate_relationships([ev("a"), ev("a", source="gmail")], REGISTRY)


def test_below_review_threshold_pairs_are_not_emitted_but_counted():
    a = ev("a", source="log", actor=None, action="observation", account_id=None, integrity_status="MISSING")
    b = ev("b", source="log", actor=None, action="observation", account_id=None,
           integrity_status="MISSING", timestamp="2026-11-24T10:01:00Z")
    result = correlate_relationships([a, b], REGISTRY)
    assert result.relationship_count == 0
    assert result.metadata["below_threshold_pair_count"] == 1


def test_result_metadata_contains_candidate_and_registry_details():
    result = correlate_relationships([], REGISTRY)
    assert result.metadata["candidate_pair_count"] == 0
    assert result.metadata["registry_hash"] == REGISTRY.registry_hash
    assert result.metadata["threshold_status"] == "PROVISIONAL"
    assert result.to_dict()["relationships"] == []
