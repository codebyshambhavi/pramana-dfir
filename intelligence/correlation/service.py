"""Case-scoped service boundary for backend integration without persistence ownership."""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from .orchestration import CorrelationInputError, CorrelationResult, correlate_relationships
from .registry import Registry


def registry_description(registry: Registry) -> dict[str, Any]:
    """Return the authoritative, versioned registry payload for a read-only API."""
    return registry.describe(include_parameters=True)


def correlate_case_events(
    case_id: str,
    events: Sequence[Mapping[str, Any]],
    registry: Registry,
    *,
    source_clocks=None,
    evidence_context=None,
) -> CorrelationResult:
    """Run correlation for exactly one case; reject cross-case payloads."""
    if not isinstance(case_id, str) or not case_id.strip():
        raise CorrelationInputError("case_id must be a non-empty string")
    if any(event.get("case_id") != case_id for event in events):
        raise CorrelationInputError("all events must belong to the requested case_id")
    return correlate_relationships(
        events, registry, source_clocks=source_clocks, evidence_context=evidence_context
    )
