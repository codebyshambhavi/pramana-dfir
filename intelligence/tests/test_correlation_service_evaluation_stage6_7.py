import pytest

from intelligence.correlation import (
    CorrelationInputError,
    correlate_case_events,
    evaluate_labelled_pairs,
    load_registry,
    registry_description,
)

REGISTRY = load_registry()


def event(eid, **kwargs):
    base = {
        "event_id": eid, "case_id": "case-1", "source": "log",
        "timestamp": "2026-11-24T10:00:00Z", "action": "login",
        "actor": "alice@example.org", "account_id": "acct-1",
        "integrity_status": "MATCH", "parser_confidence": 1.0,
        "acquisition_method": "vendor_export", "raw": {},
    }
    base.update(kwargs)
    return base


def test_case_service_rejects_mixed_case_events():
    with pytest.raises(CorrelationInputError, match="requested case_id"):
        correlate_case_events("case-1", [event("a"), event("b", case_id="case-2")], REGISTRY)


def test_case_service_returns_case_scoped_result():
    result = correlate_case_events(
        "case-1",
        [event("a"), event("b", timestamp="2026-11-24T10:02:00Z")],
        REGISTRY,
    )
    assert result.metadata["event_count"] == 2
    assert all(x["case_id"] == "case-1" for x in result.relationships)


def test_registry_description_is_versioned_and_has_counts():
    payload = registry_description(REGISTRY)
    assert payload["registry_hash"] == REGISTRY.registry_hash
    assert payload["counts"]["total_registered"] == 45
    assert payload["counts"]["enabled"] == 44


def test_labelled_pair_evaluator_reports_confusion_matrix_and_metrics():
    h = "f" * 64
    a = event("a", source="gmail", raw={"attachments": [{"filename": "x.pdf", "sha256": h}]})
    b = event("b", source="log", object=h)
    c = event("c", source="log", actor=None, action="observation", account_id=None,
              integrity_status="MISSING", timestamp="2026-11-24T10:01:00Z")
    d = event("d", source="log", actor=None, action="observation", account_id=None,
              integrity_status="MISSING", timestamp="2026-11-24T10:02:00Z")
    report = evaluate_labelled_pairs([
        {"event_a": a, "event_b": b, "label": True, "relationship_type": "PRIMARY"},
        {"event_a": c, "event_b": d, "label": False, "relationship_type": "UNRELATED"},
    ], REGISTRY, split="held_out")
    assert report["sample_count"] == 2
    assert report["confusion_matrix"] == {
        "true_positive": 1, "false_positive": 0,
        "true_negative": 1, "false_negative": 0,
    }
    assert report["precision"] == 1.0
    assert report["recall"] == 1.0
    assert report["threshold_status"] == "PROVISIONAL"


def test_labelled_pair_evaluator_rejects_cross_case_and_duplicate_pairs():
    a, b = event("a"), event("b")
    with pytest.raises(ValueError, match="same non-empty case"):
        evaluate_labelled_pairs([{"event_a": a, "event_b": event("x", case_id="case-2"), "label": True}], REGISTRY)
    with pytest.raises(ValueError, match="duplicate labelled pair"):
        evaluate_labelled_pairs([
            {"event_a": a, "event_b": b, "label": True},
            {"event_a": b, "event_b": a, "label": True},
        ], REGISTRY)


def test_evaluator_does_not_accept_unspecified_split():
    with pytest.raises(ValueError, match="split"):
        evaluate_labelled_pairs([], REGISTRY, split="train")
