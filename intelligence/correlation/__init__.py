"""Role 1 correlation engine: versioned, registry-driven, deterministic and explainable.

This package sits beside the existing T5/T6 link engine (``intelligence.correlate`` /
``intelligence.claims``), which it does not modify or replace. The parameter registry
(``registry_v1.json``) holds every weight, threshold and window; the Python modules
only implement generic, deterministic building blocks the registry refers to.

No LLM is involved anywhere in this package.
"""
from __future__ import annotations

from .registry import (
    DEFAULT_REGISTRY_VERSION,
    Parameter,
    Registry,
    RegistryError,
    RegistryValidationError,
    RegistryVersionError,
    UnknownParameterError,
    available_versions,
    iter_fixtures,
    load_registry,
    load_registry_from_dict,
    load_registry_from_path,
    validate_document,
)

__all__ = [
    "DEFAULT_REGISTRY_VERSION",
    "Parameter",
    "Registry",
    "RegistryError",
    "RegistryValidationError",
    "RegistryVersionError",
    "UnknownParameterError",
    "available_versions",
    "iter_fixtures",
    "load_registry",
    "load_registry_from_dict",
    "load_registry_from_path",
    "validate_document",
]

# Stage 3/4 public building blocks. Imported lazily by consumers that need the
# engine; these remain separate from the legacy T5/T6 claim-generation API.
from .fields import ResolvedField, resolve_event, resolve_field
from .anchors import AnchorResult, evaluate_anchor, evaluate_anchors, generate_candidate_pairs
from .features import Signal, evaluate_features, evaluate_parameter, evaluate_reliability
from .scorer import score_pair

__all__ += [
    "ResolvedField", "resolve_event", "resolve_field",
    "AnchorResult", "evaluate_anchor", "evaluate_anchors", "generate_candidate_pairs",
    "Signal", "evaluate_features", "evaluate_parameter", "evaluate_reliability", "score_pair",
]

# Stage 5 orchestration and deterministic explanations.
from .explain import explain_primary, explain_secondary
from .orchestration import CorrelationInputError, CorrelationResult, correlate_relationships

__all__ += [
    "explain_primary", "explain_secondary",
    "CorrelationInputError", "CorrelationResult", "correlate_relationships",
]

# Stage 6/7: case-scoped service boundary and labelled-pair evaluation.
from .service import correlate_case_events, registry_description
from .evaluate import evaluate_labelled_pairs

__all__ += ["correlate_case_events", "registry_description", "evaluate_labelled_pairs"]
