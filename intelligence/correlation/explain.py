"""Deterministic, evidence-grounded explanations for correlation relationships."""
from __future__ import annotations

from typing import Any, Mapping, Sequence


def explain_primary(anchors: Sequence[Mapping[str, Any]]) -> str:
    valid = [a for a in anchors if a.get("status") == "ANCHORED"]
    if not valid:
        return "A direct relationship was not established by a validated anchor."
    labels = sorted({str(a.get("anchor_type") or a.get("parameter_id") or "direct identifier") for a in valid})
    details = "; ".join(str(a.get("explanation", "Validated direct identifier match.")) for a in valid)
    return f"Primary relationship established by {', '.join(labels)}. {details}"


def explain_secondary(score_result: Mapping[str, Any], *, max_signals: int = 3) -> str:
    """Summarise the largest deterministic contributions without inventing causality."""
    contributions = list(score_result.get("feature_contributions") or [])
    positives = sorted(
        (c for c in contributions if c.get("kind") == "feature" and float(c.get("contribution") or 0) > 0),
        key=lambda c: (-float(c.get("contribution") or 0), str(c.get("parameter_id", ""))),
    )
    negatives = sorted(
        (c for c in contributions if float(c.get("amount") or 0) < 0),
        key=lambda c: (float(c.get("amount") or 0), str(c.get("parameter_id", ""))),
    )
    unavailable = sorted(set(score_result.get("unavailable_parameters") or []))
    status = str(score_result.get("status", "BELOW_THRESHOLD"))
    score = float(score_result.get("score", 0.0))
    if positives:
        support = ", ".join(
            f"{c.get('parameter_id')} (+{float(c.get('contribution') or 0):.3f})"
            for c in positives[:max_signals]
        )
    else:
        support = "no positive feature contribution"
    if negatives:
        counter = ", ".join(
            f"{c.get('parameter_id')} ({float(c.get('amount') or 0):.3f})"
            for c in negatives[:max_signals]
        )
        counter_text = f" Counter-signals include {counter}."
    else:
        counter_text = " No negative contribution was recorded."
    missing_text = f" Unavailable signals: {', '.join(unavailable[:max_signals])}." if unavailable else ""
    if status == "HIGH_CONFIDENCE":
        disposition = "The provisional high-confidence threshold was met"
    elif status == "ANALYST_REVIEW":
        disposition = "The provisional review threshold was met; analyst review is required"
    else:
        disposition = "The pair did not meet the review threshold"
    return f"Secondary score {score:.3f}; {disposition}. Supporting signals: {support}.{counter_text}{missing_text}"
