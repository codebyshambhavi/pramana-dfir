from __future__ import annotations

from bench.baselines import time_window_only, time_window_shared_identifier
from bench.metrics import aggregate_metrics, scenario_metrics
from bench.run import _stable_output


def test_link_baselines_apply_expected_identifier_filter():
    events = [
        {
            "event_id": "a",
            "artifact_ref": "a.csv#row=1",
            "evidence_id": "e1",
            "timestamp": "2026-10-17T22:00:00+00:00",
            "source": "log",
            "actor": "mira",
            "device": "laptop",
            "object": "archive.zip",
        },
        {
            "event_id": "b",
            "artifact_ref": "b.csv#row=1",
            "evidence_id": "e2",
            "timestamp": "2026-10-17T22:05:00+00:00",
            "source": "browser",
            "actor": "mira",
            "device": "laptop",
            "object": "archive.zip",
        },
        {
            "event_id": "c",
            "artifact_ref": "c.csv#row=1",
            "evidence_id": "e3",
            "timestamp": "2026-10-17T22:06:00+00:00",
            "source": "browser",
            "actor": "unrelated",
            "device": "different",
            "object": "unrelated.txt",
        },
    ]
    assert len(time_window_only(events)["links"]) == 3
    assert time_window_shared_identifier(events)["links"] == [
        ("a.csv#row=1", "b.csv#row=1")
    ]


def test_metrics_counts_and_zero_denominators_are_explicit():
    truth = {
        "true_links": [{"from": "a", "to": "b"}],
        "decoy_events": ["decoy"],
        "correct_hypothesis": "UNDETERMINED",
        "contradictions": [{"event_refs": ["a", "b"]}],
        "absence_classification": {"H2-EXP-2": "MISSING"},
        "tamper_descendants": [],
    }
    prediction = {
        "links": [("a", "b"), ("a", "decoy")],
        "top_hypothesis": "H1",
        "contradictions": [{"event_refs": ["a", "b"]}],
        "absence_classification": {"H2-EXP-2": "MISSING"},
        "claim_lineage": {"resolved": 1, "total": 2},
    }
    result = scenario_metrics(prediction, truth)
    assert result["link_precision"] == {
        "numerator": 1, "denominator": 2, "percentage": 50.0, "unavailable_reason": None
    }
    assert result["link_recall"]["percentage"] == 100.0
    assert result["decoy_false_positive_rate"]["numerator"] == 1
    assert result["over_claim_rate"]["numerator"] == 1
    assert result["missing_unobservable_accuracy"]["percentage"] == 100.0
    assert result["tamper_invalidation_accuracy"]["percentage"] is None


def test_aggregate_metrics_sum_counts_and_preserve_unavailable_values():
    aggregate = aggregate_metrics([
        (
            {"links": [], "top_hypothesis": "H1"},
            {"true_links": [], "correct_hypothesis": "H1"},
        ),
        (
            {"links": [], "top_hypothesis": None},
            {"true_links": [], "correct_hypothesis": "H2"},
        ),
    ])
    assert aggregate["scenario_count"] == 2
    assert aggregate["metrics"]["link_precision"]["percentage"] is None
    assert aggregate["metrics"]["top_hypothesis_accuracy"]["numerator"] == 1
    assert aggregate["metrics"]["top_hypothesis_accuracy"]["denominator"] == 1


def test_tamper_accuracy_compares_actual_invalidated_links_to_ground_truth():
    result = scenario_metrics(
        {"invalidated_descendants": [("archive", "upload")]},
        {"tamper_descendants": [{"from": "upload", "to": "archive"}]},
    )
    assert result["tamper_invalidation_accuracy"]["numerator"] == 1
    assert result["tamper_invalidation_accuracy"]["denominator"] == 1
    assert result["tamper_invalidation_accuracy"]["percentage"] == 100.0
    mismatch = scenario_metrics(
        {"invalidated_descendants": [("archive", "upload"), ("extra", "event")]},
        {"tamper_descendants": [{"from": "upload", "to": "archive"}]},
    )
    assert mismatch["tamper_invalidation_accuracy"]["numerator"] == 0
    assert mismatch["tamper_invalidation_accuracy"]["denominator"] == 1


def test_metrics_do_not_infer_absence_from_baseline_without_classification():
    result = scenario_metrics(
        {"links": []},
        {"absence_classification": {"H2-EXP-2": "MISSING"}},
    )
    assert result["missing_unobservable_accuracy"]["percentage"] is None
    assert result["missing_unobservable_accuracy"]["unavailable_reason"] == (
        "system did not produce absence classifications"
    )


def test_stable_output_removes_only_run_instance_metadata():
    output = _stable_output({
        "run_id": "RUN-RANDOM",
        "created_at": "2026-11-06T00:00:00Z",
        "nested": [{"run_id": "RUN-CHILD", "event_id": "event-1"}],
    })
    assert output == {"nested": [{"event_id": "event-1"}]}
