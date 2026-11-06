"""Ground-truth metrics for synthetic PRAMANA benchmark runs."""
from __future__ import annotations

from typing import Any, Iterable


def _pairs(values: Iterable[Any]) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for value in values:
        if isinstance(value, dict):
            first, second = value.get("from"), value.get("to")
        else:
            try:
                first, second = value
            except (TypeError, ValueError):
                continue
        if first is not None and second is not None:
            pairs.add(tuple(sorted((str(first), str(second)))))
    return pairs


def _metric(numerator: int, denominator: int, *, reason: str | None = None) -> dict[str, Any]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "percentage": (100.0 * numerator / denominator) if denominator else None,
        "unavailable_reason": reason if denominator == 0 else None,
    }


def scenario_metrics(prediction: dict[str, Any], ground_truth: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one system prediction without filling missing output with guesses."""
    expected_links = _pairs(ground_truth.get("true_links", []))
    predicted_links = _pairs(prediction.get("links", []))
    correct_links = expected_links & predicted_links
    decoys = set(ground_truth.get("decoy_events", []))
    predicted_decoys = {
        ref
        for pair in predicted_links
        for ref in pair
        if ref in decoys
    }

    expected_hypothesis = ground_truth.get("correct_hypothesis")
    predicted_hypothesis = prediction.get("top_hypothesis")
    has_hypothesis = predicted_hypothesis is not None
    correct_undetermined = (
        expected_hypothesis == "UNDETERMINED"
        and predicted_hypothesis == "UNDETERMINED"
    )
    overclaim = (
        expected_hypothesis == "UNDETERMINED"
        and predicted_hypothesis is not None
        and predicted_hypothesis != "UNDETERMINED"
    )
    hypothesis_correct = has_hypothesis and predicted_hypothesis == expected_hypothesis

    expected_contradictions = {
        tuple(sorted(map(str, item.get("event_refs", []))))
        for item in ground_truth.get("contradictions", [])
    }
    has_contradiction_output = "contradictions" in prediction
    predicted_contradictions = set()
    for item in prediction.get("contradictions", []):
        if isinstance(item, dict) and isinstance(item.get("event_refs"), list):
            refs = item["event_refs"]
            if len(refs) >= 2:
                predicted_contradictions.add(tuple(sorted(map(str, refs[:2]))))
        else:
            predicted_contradictions.update(_pairs([item]))

    expected_absence = ground_truth.get("absence_classification", {})
    predicted_absence = prediction.get("absence_classification", {})
    has_absence_output = "absence_classification" in prediction
    absence_denominator = len(expected_absence) if has_absence_output else 0
    absence_correct = sum(
        1
        for item, expected in expected_absence.items()
        if isinstance(predicted_absence, dict) and predicted_absence.get(item) == expected
    )

    lineage = prediction.get("claim_lineage")
    lineage_resolved = int(lineage.get("resolved", 0)) if isinstance(lineage, dict) else 0
    lineage_total = int(lineage.get("total", 0)) if isinstance(lineage, dict) else 0

    expected_invalidated = _pairs(ground_truth.get("tamper_descendants", []))
    actual_invalidated = _pairs(prediction.get("invalidated_descendants", []))
    has_tamper_output = "invalidated_descendants" in prediction
    tamper_denominator = int(has_tamper_output)
    tamper_correct = int(
        has_tamper_output and expected_invalidated == actual_invalidated
    )

    return {
        "link_precision": _metric(len(correct_links), len(predicted_links)),
        "link_recall": _metric(len(correct_links), len(expected_links)),
        "decoy_false_positive_rate": _metric(len(predicted_decoys), len(decoys)),
        "top_hypothesis_accuracy": _metric(
            int(hypothesis_correct),
            int(has_hypothesis),
            reason="system did not produce a top-hypothesis prediction",
        ),
        "correct_undetermined_rate": _metric(
            int(correct_undetermined),
            int(has_hypothesis and expected_hypothesis == "UNDETERMINED"),
            reason="system did not produce a top-hypothesis prediction",
        ),
        "over_claim_rate": _metric(
            int(overclaim),
            int(has_hypothesis and expected_hypothesis == "UNDETERMINED"),
            reason="system did not produce a top-hypothesis prediction",
        ),
        "contradiction_recall": _metric(
            len(expected_contradictions & predicted_contradictions),
            len(expected_contradictions) if has_contradiction_output else 0,
            reason="system did not produce contradiction predictions",
        ),
        "missing_unobservable_accuracy": _metric(
            absence_correct,
            absence_denominator,
            reason="system did not produce absence classifications",
        ),
        "claim_lineage_resolution_rate": _metric(
            lineage_resolved,
            lineage_total,
            reason="system did not expose claim lineage counts",
        ),
        "tamper_invalidation_accuracy": _metric(
            tamper_correct,
            tamper_denominator,
            reason="system did not produce tamper invalidation predictions",
        ),
        "raw": {
            "correct_links": len(correct_links),
            "predicted_links": len(predicted_links),
            "expected_links": len(expected_links),
            "decoy_false_positives": len(predicted_decoys),
            "decoy_events": len(decoys),
            "hypothesis_available": has_hypothesis,
            "hypothesis_correct": bool(hypothesis_correct),
            "correct_undetermined": bool(correct_undetermined),
            "over_claim": bool(overclaim),
            "contradictions_found": len(expected_contradictions & predicted_contradictions),
            "contradictions_expected": len(expected_contradictions),
            "absence_correct": absence_correct,
            "absence_classifications_expected": absence_denominator,
            "claim_lineage_resolved": lineage_resolved,
            "claim_lineage_total": lineage_total,
            "tamper_cases_exactly_matched": tamper_correct,
            "tamper_cases_evaluated": tamper_denominator,
            "tamper_descendants_matched": len(expected_invalidated & actual_invalidated),
            "tamper_descendants_expected": len(expected_invalidated),
            "tamper_descendants_actual": len(actual_invalidated),
        },
    }


def aggregate_metrics(
    items: list[tuple[dict[str, Any], dict[str, Any]]],
) -> dict[str, Any]:
    """Aggregate scenario metrics using summed counts, preserving safe zero ratios."""
    per_scenario = [scenario_metrics(prediction, truth) for prediction, truth in items]
    metric_names = (
        "link_precision",
        "link_recall",
        "decoy_false_positive_rate",
        "top_hypothesis_accuracy",
        "correct_undetermined_rate",
        "over_claim_rate",
        "contradiction_recall",
        "missing_unobservable_accuracy",
        "claim_lineage_resolution_rate",
        "tamper_invalidation_accuracy",
    )
    totals: dict[str, Any] = {}
    for name in metric_names:
        numerator = sum(metric[name]["numerator"] for metric in per_scenario)
        denominator = sum(metric[name]["denominator"] for metric in per_scenario)
        reasons = sorted({
            str(metric[name]["unavailable_reason"])
            for metric in per_scenario
            if metric[name]["unavailable_reason"]
        })
        totals[name] = _metric(
            numerator,
            denominator,
            reason="; ".join(reasons) if reasons else None,
        )
    return {"scenario_count": len(items), "metrics": totals}
