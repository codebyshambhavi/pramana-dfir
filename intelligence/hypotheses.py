"""Deterministic alternative explanations for Role 2 findings."""
from __future__ import annotations

import copy


def _alternatives(finding_type: str) -> list[dict]:
    if finding_type == "contradiction":
        return [
            {
                "claim": "One or more source timestamps or measurements may be inaccurate or delayed.",
                "confidence": 0.40,
                "needed_evidence": [
                    "Original source metadata and acquisition timestamps",
                    "Device clock or synchronization records",
                ],
            },
            {
                "claim": "The observed events may have an alternative operational explanation.",
                "confidence": 0.35,
                "needed_evidence": [
                    "Related device, custody, or system records",
                    "Additional events covering the same interval",
                ],
            },
            {
                "claim": "The records may refer to different physical or logical contexts.",
                "confidence": 0.25,
                "needed_evidence": [
                    "Artifact provenance and device association",
                    "Independent corroborating artifacts",
                ],
            },
        ]

    if finding_type == "anomaly":
        return [
            {
                "claim": "The activity may be legitimate scheduled or user-initiated activity.",
                "confidence": 0.40,
                "needed_evidence": [
                    "User schedule or authorization records",
                    "Related activity from the same period",
                ],
            },
            {
                "claim": "The activity may have been generated automatically by a background process.",
                "confidence": 0.35,
                "needed_evidence": [
                    "Process or service logs",
                    "System task or automation records",
                ],
            },
            {
                "claim": "The activity may represent unexpected activity requiring investigation.",
                "confidence": 0.25,
                "needed_evidence": [
                    "Authentication or access logs",
                    "Additional correlated events",
                ],
            },
        ]

    return []


def add_hypotheses(findings: list[dict]) -> list[dict]:
    """Attach deterministic alternatives to contradiction/anomaly Findings.

    The input findings are not mutated. Alternative confidence values sum to
    1.0 and use only fields allowed by the frozen Finding schema.
    """
    output: list[dict] = []

    for original in findings:
        finding = copy.deepcopy(original)
        finding_type = finding.get("type")

        if finding_type in {"contradiction", "anomaly"}:
            finding["alternatives"] = _alternatives(finding_type)

        output.append(finding)

    return output
