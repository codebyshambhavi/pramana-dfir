"""Labelled-pair evaluation helpers; no fitting or calibration is performed here."""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from .anchors import evaluate_anchors
from .registry import Registry
from .scorer import score_pair


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def evaluate_labelled_pairs(
    labelled_pairs: Sequence[Mapping[str, Any]],
    registry: Registry,
    *,
    clocks=None,
    evidence_context=None,
    split: str = "held_out",
) -> dict[str, Any]:
    """Evaluate labelled event pairs using review-threshold decisions.

    Each item must contain ``event_a``, ``event_b`` and boolean ``label``.
    This function only measures the supplied split; it never tunes weights or
    thresholds and must not be described as real-world performance when the
    supplied examples are synthetic.
    """
    if split not in {"development", "held_out"}:
        raise ValueError("split must be 'development' or 'held_out'")
    tp = fp = tn = fn = 0
    per_class: dict[str, dict[str, int]] = {}
    seen: set[tuple[str, str, str]] = set()
    for index, item in enumerate(labelled_pairs):
        if not isinstance(item, Mapping):
            raise ValueError(f"labelled_pairs[{index}] must be a mapping")
        a, b, label = item.get("event_a"), item.get("event_b"), item.get("label")
        if not isinstance(a, Mapping) or not isinstance(b, Mapping) or not isinstance(label, bool):
            raise ValueError(f"labelled_pairs[{index}] requires event_a/event_b mappings and boolean label")
        case_a, case_b = str(a.get("case_id") or ""), str(b.get("case_id") or "")
        if not case_a or case_a != case_b:
            raise ValueError(f"labelled_pairs[{index}] must contain two events from the same non-empty case")
        id_a, id_b = str(a.get("event_id") or ""), str(b.get("event_id") or "")
        if not id_a or not id_b or id_a == id_b:
            raise ValueError(f"labelled_pairs[{index}] requires two distinct event IDs")
        pair_key = (case_a, *sorted((id_a, id_b)))
        if pair_key in seen:
            raise ValueError(f"duplicate labelled pair at index {index}: {pair_key}")
        seen.add(pair_key)
        anchors = evaluate_anchors(a, b, registry, evidence_context=evidence_context)
        predicted_type = None
        if any(anchor.status == "ANCHORED" for anchor in anchors):
            predicted = True
            predicted_type = "PRIMARY"
        else:
            scored = score_pair(a, b, registry, events=[a, b], clocks=clocks, evidence_context=evidence_context)
            predicted = scored["status"] in {"ANALYST_REVIEW", "HIGH_CONFIDENCE"}
            if predicted:
                predicted_type = "SECONDARY"
        if predicted and label:
            tp += 1
        elif predicted and not label:
            fp += 1
        elif not predicted and not label:
            tn += 1
        else:
            fn += 1
        expected_type = str(item.get("relationship_type") or "UNSPECIFIED").upper()
        bucket = per_class.setdefault(expected_type, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
        if predicted and label:
            bucket["tp"] += 1
        elif predicted and not label:
            bucket["fp"] += 1
        elif not predicted and not label:
            bucket["tn"] += 1
        else:
            bucket["fn"] += 1

    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    fpr = _ratio(fp, fp + tn)
    fnr = _ratio(fn, fn + tp)
    f1 = (2 * precision * recall / (precision + recall)) if precision is not None and recall is not None and precision + recall else None
    return {
        "split": split,
        "sample_count": len(labelled_pairs),
        "confusion_matrix": {"true_positive": tp, "false_positive": fp, "true_negative": tn, "false_negative": fn},
        "precision": precision,
        "recall": recall,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "f1": f1,
        "per_expected_relationship_type": {
            key: {
                **counts,
                "precision": _ratio(counts["tp"], counts["tp"] + counts["fp"]),
                "recall": _ratio(counts["tp"], counts["tp"] + counts["fn"]),
            }
            for key, counts in sorted(per_class.items())
        },
        "registry_version": registry.registry_version,
        "registry_hash": registry.registry_hash,
        "config_version": registry.config_version,
        "calibration_status": registry.calibration_status,
        "threshold_status": "PROVISIONAL" if registry.is_provisional else "CALIBRATED",
        "limitations": [
            "Metrics describe only the supplied labelled pairs and split.",
            "This evaluator does not fit or calibrate weights or thresholds.",
            "Synthetic fixtures are not evidence of real-world accuracy.",
        ],
    }
