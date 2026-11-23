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


def test_b1_does_not_stop_after_a_pair_outside_the_time_window():
    from bench.baselines import time_window_only

    events = [
        {
            "event_id": "a",
            "artifact_ref": "a.csv#row=1",
            "evidence_id": "e1",
            "timestamp": "2026-10-17T22:00:00+00:00",
            "source": "log",
        },
        {
            "event_id": "b",
            "artifact_ref": "b.csv#row=1",
            "evidence_id": "e2",
            "timestamp": "2026-10-17T23:00:00+00:00",
            "source": "browser",
        },
        {
            "event_id": "c",
            "artifact_ref": "c.csv#row=1",
            "evidence_id": "e3",
            "timestamp": "2026-10-17T23:05:00+00:00",
            "source": "vpn",
        },
    ]

    assert time_window_only(events, window_minutes=15)["links"] == [
        ("b.csv#row=1", "c.csv#row=1")
    ]


def _hypothesis_metrics(predicted, expected):
    return scenario_metrics(
        {"top_hypothesis": predicted},
        {"correct_hypothesis": expected},
    )


def test_selective_accuracy_counts_only_commitments_not_abstentions():
    correct = _hypothesis_metrics("H1", "H1")
    assert correct["selective_accuracy"]["numerator"] == 1
    assert correct["selective_accuracy"]["denominator"] == 1
    assert correct["abstention_rate"]["denominator"] == 1
    assert correct["abstention_rate"]["numerator"] == 0

    wrong = _hypothesis_metrics("H2", "H1")
    assert wrong["selective_accuracy"]["numerator"] == 0
    assert wrong["selective_accuracy"]["denominator"] == 1

    # A commitment on a case whose truth is UNDETERMINED is an incorrect commitment.
    overclaim = _hypothesis_metrics("H1", "UNDETERMINED")
    assert overclaim["selective_accuracy"]["numerator"] == 0
    assert overclaim["selective_accuracy"]["denominator"] == 1
    assert overclaim["abstention_rate"]["denominator"] == 0


def test_correct_abstention_is_not_a_successful_commitment():
    result = _hypothesis_metrics("UNDETERMINED", "UNDETERMINED")
    assert result["selective_accuracy"]["denominator"] == 0
    assert result["selective_accuracy"]["percentage"] is None
    assert result["selective_accuracy"]["unavailable_reason"]
    assert result["abstention_rate"]["denominator"] == 0
    assert result["correct_undetermined_rate"]["numerator"] == 1


def test_abstention_on_definite_truth_is_counted_separately_from_wrong_answers():
    result = _hypothesis_metrics("UNDETERMINED", "H1")
    assert result["abstention_rate"]["numerator"] == 1
    assert result["abstention_rate"]["denominator"] == 1
    assert result["selective_accuracy"]["denominator"] == 0
    assert result["top_hypothesis_accuracy"]["numerator"] == 0


def test_missing_hypothesis_prediction_is_unavailable_for_every_hypothesis_metric():
    result = scenario_metrics({"links": []}, {"correct_hypothesis": "H1"})
    for name in (
        "top_hypothesis_accuracy",
        "selective_accuracy",
        "abstention_rate",
        "over_claim_rate",
        "correct_undetermined_rate",
    ):
        assert result[name]["denominator"] == 0, name
        assert result[name]["percentage"] is None, name

    none_prediction = _hypothesis_metrics(None, "H1")
    assert none_prediction["selective_accuracy"]["denominator"] == 0
    assert none_prediction["abstention_rate"]["denominator"] == 0


def test_aggregate_selective_accuracy_and_abstention_rate_sum_counts():
    cases = [("H1", "H1"), ("H2", "H1"), ("UNDETERMINED", "H1"), ("UNDETERMINED", "UNDETERMINED")]
    aggregate = aggregate_metrics([
        ({"top_hypothesis": predicted}, {"correct_hypothesis": expected})
        for predicted, expected in cases
    ])["metrics"]
    assert (aggregate["selective_accuracy"]["numerator"],
            aggregate["selective_accuracy"]["denominator"]) == (1, 2)
    assert (aggregate["abstention_rate"]["numerator"],
            aggregate["abstention_rate"]["denominator"]) == (1, 3)
    # Existing metric keeps its documented meaning: includes the correct abstention.
    assert (aggregate["top_hypothesis_accuracy"]["numerator"],
            aggregate["top_hypothesis_accuracy"]["denominator"]) == (2, 4)


def test_duplicate_equivalence_metrics_are_additive_and_do_not_replace_strict_scores():
    truth = {
        "true_links": [{"from": "duplicate.csv#row=2", "to": "other.csv#row=7"}],
        "duplicate_rows": [
            {"duplicate": "duplicate.csv#row=2", "original": "duplicate.csv#row=1"}
        ],
        "tamper_descendants": [
            {"from": "duplicate.csv#row=2", "to": "other.csv#row=7"}
        ],
    }
    prediction = {
        "links": [("duplicate.csv#row=1", "other.csv#row=7")],
        "invalidated_descendants": [("duplicate.csv#row=1", "other.csv#row=7")],
    }
    result = scenario_metrics(prediction, truth)

    # Strict artifact-reference metrics remain unchanged and expose the mismatch.
    assert result["link_recall"]["percentage"] == 0.0
    assert result["tamper_invalidation_accuracy"]["percentage"] == 0.0

    # Equivalence-aware metrics recognize that row 1 and row 2 are duplicates.
    assert result["link_recall_equivalence_aware"]["percentage"] == 100.0
    assert result["link_precision_equivalence_aware"]["percentage"] == 100.0
    assert result["tamper_invalidation_equivalence_aware_accuracy"]["percentage"] == 100.0


def test_hypothesis_metrics_are_unavailable_when_ground_truth_is_undefined():
    result = scenario_metrics({"top_hypothesis": "H1"}, {})
    for name in (
        "top_hypothesis_accuracy",
        "selective_accuracy",
        "abstention_rate",
        "correct_undetermined_rate",
        "over_claim_rate",
    ):
        assert result[name]["denominator"] == 0, name
        assert result[name]["percentage"] is None, name


def test_zero_denominator_reasons_distinguish_missing_output_from_empty_ground_truth():
    missing_output = scenario_metrics({}, {"contradictions": [{"event_refs": ["a", "b"]}]})
    assert missing_output["contradiction_recall"]["unavailable_reason"] == (
        "system did not produce contradiction predictions"
    )

    no_expected = scenario_metrics({"contradictions": []}, {"contradictions": []})
    assert no_expected["contradiction_recall"]["unavailable_reason"] == (
        "ground truth contains no expected contradictions"
    )
