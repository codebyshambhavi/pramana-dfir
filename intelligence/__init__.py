"""Role 2 entry point used by the backend.

The public contract is:
    intelligence.analyze(events) -> list[dict]

The pipeline is deterministic and evidence-first:
correlation -> anomalies -> contradictions -> hypotheses -> authenticity.

Every returned Finding is validated against the frozen Finding schema.
"""

from __future__ import annotations

from typing import Any

from . import common
from .anomalies import find_anomalies
from .authenticity import score_image
from .contradictions import find_contradictions
from .correlate import correlate
from .hypotheses import add_hypotheses


def _merge_findings(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge, validate, de-duplicate and deterministically order findings."""
    merged: dict[str, dict[str, Any]] = {}

    for group in groups:
        for finding in group:
            common.validate_finding(finding)

            if not finding.get("needs_human_review", False):
                raise ValueError(
                    f"Role 2 finding {finding.get('finding_id', '<unknown>')} "
                    "must require human review."
                )

            finding_id = finding["finding_id"]
            existing = merged.get(finding_id)

            if existing is None:
                merged[finding_id] = finding
            elif existing != finding:
                raise ValueError(
                    f"Conflicting findings share finding_id={finding_id!r}."
                )

    return [merged[key] for key in sorted(merged)]


def analyze(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run the complete deterministic Role 2 intelligence pipeline."""
    if not events:
        return []

    correlation_findings = correlate(events)
    anomaly_findings = find_anomalies(events)
    contradiction_findings = find_contradictions(events)

    # Attach alternative explanations to anomaly/contradiction findings.
    rule_findings = add_hypotheses(
        correlation_findings
        + anomaly_findings
        + contradiction_findings
    )

    # Authenticity triage applies only when image Events exist.
    image_events = [
        event for event in events
        if event.get("source") == "image"
    ]

    authenticity_findings: list[dict[str, Any]] = []

    if image_events:
        authenticity_result = score_image(image_events)
        authenticity_findings = [authenticity_result["finding"]]

    return _merge_findings(
        rule_findings,
        authenticity_findings,
    )