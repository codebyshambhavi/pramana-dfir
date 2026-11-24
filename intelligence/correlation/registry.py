"""Versioned, data-driven correlation parameter registry.

The registry file (``registry_<tag>.json``) is the single place where parameters,
weights, thresholds, windows and reference data are defined. This module only

* loads and *validates* a registry document (collecting every problem),
* exposes lookup / filtering / counting,
* computes a deterministic content hash, and
* exports a description for ``GET /correlation/registry``.

No weight, threshold or feature name is hard-coded here. The closed vocabularies
a registry may refer to live in ``vocabulary.py``.

Everything in the shipped registry is ``PROVISIONAL`` until calibrated on
representative labelled data (see ``evaluate.py``); ``calibration.status``
records that and validation refuses to mix PROVISIONAL and CALIBRATED states
inconsistently.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Iterable, Mapping

from . import vocabulary as V

PACKAGE_DIR = Path(__file__).resolve().parent
REGISTRY_FILE_GLOB = "registry_*.json"
SUPPORTED_SCHEMA_VERSIONS = ("1",)
DEFAULT_REGISTRY_VERSION = "corr-registry-v1"

_PARAM_ID = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_VERSION_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

PARAMETER_REQUIRED_KEYS = (
    "parameter_id", "display_name", "description", "family", "role", "direction",
    "relation_type", "applies_to_sources", "source_fields", "extraction_method",
    "normalisation_rule", "weight", "weight_status", "reliability_rule",
    "missing_value_policy", "collision_penalty_rule", "version", "status",
    "effective_date", "change_reason", "fixtures",
)
TOP_LEVEL_REQUIRED_KEYS = (
    "schema_version", "registry_version", "config_version", "effective_date",
    "change_reason", "calibration", "score_model", "thresholds",
    "candidate_generation", "reference_data", "parameters",
)


class RegistryError(ValueError):
    """Base class for registry problems."""


class RegistryVersionError(RegistryError):
    """Requested registry version does not exist or is malformed."""


class RegistryValidationError(RegistryError):
    """The registry document is invalid. ``errors`` lists every problem found."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("invalid correlation registry: " + "; ".join(self.errors))


class UnknownParameterError(RegistryError, KeyError):
    pass


# ---------------------------------------------------------------------------
# Parameter
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Parameter:
    """One registry parameter. ``spec`` is the validated JSON object (deep-copied)."""

    spec: Mapping[str, Any]

    # --- convenience accessors ------------------------------------------------
    @property
    def parameter_id(self) -> str:
        return self.spec["parameter_id"]

    @property
    def role(self) -> str:
        return self.spec["role"]

    @property
    def family(self) -> str:
        return self.spec["family"]

    @property
    def direction(self) -> str:
        return self.spec["direction"]

    @property
    def relationship_class(self) -> str:
        return V.ROLE_TO_RELATIONSHIP_CLASS[self.spec["role"]]

    @property
    def enabled(self) -> bool:
        return self.spec["status"] == "ENABLED"

    @property
    def weight(self) -> float | None:
        return self.spec["weight"]

    @property
    def weight_status(self) -> str:
        return self.spec["weight_status"]

    @property
    def source_fields(self) -> tuple[str, ...]:
        return tuple(self.spec["source_fields"])

    @property
    def extraction(self) -> Mapping[str, Any]:
        return self.spec["extraction_method"]

    @property
    def normalisation(self) -> Mapping[str, Any]:
        return self.spec["normalisation_rule"]

    @property
    def reliability_rule(self) -> Mapping[str, Any] | None:
        return self.spec["reliability_rule"]

    @property
    def missing_policy(self) -> Mapping[str, Any]:
        return self.spec["missing_value_policy"]

    @property
    def collision_rule(self) -> Mapping[str, Any] | None:
        return self.spec["collision_penalty_rule"]

    @property
    def relation_types(self) -> tuple[str, ...]:
        return tuple(self.spec["relation_type"])

    @property
    def applies_to_sources(self) -> tuple[str, ...]:
        return tuple(self.spec["applies_to_sources"])

    def applies_to_pair_kind(self, kind: str) -> bool:
        return V.relation_type_matches(self.relation_types, kind)

    def applies_to_source(self, source: str | None) -> bool:
        allowed = self.applies_to_sources
        return "*" in allowed or (source or "").lower() in allowed

    def applies_to_pair(self, source_a: str | None, source_b: str | None) -> bool:
        return (
            self.applies_to_pair_kind(V.pair_kind(source_a, source_b))
            and self.applies_to_source(source_a)
            and self.applies_to_source(source_b)
        )

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(dict(self.spec))

    def summary(self) -> dict[str, Any]:
        s = self.spec
        return {
            "parameter_id": s["parameter_id"],
            "display_name": s["display_name"],
            "description": s["description"],
            "family": s["family"],
            "role": s["role"],
            "relationship_class": self.relationship_class,
            "direction": s["direction"],
            "relation_type": list(s["relation_type"]),
            "applies_to_sources": list(s["applies_to_sources"]),
            "source_fields": list(s["source_fields"]),
            "extraction_method": s["extraction_method"]["method"],
            "normalisation_rule": s["normalisation_rule"]["kind"],
            "weight": s["weight"],
            "weight_status": s["weight_status"],
            "missing_value_policy": s["missing_value_policy"]["policy"],
            "has_collision_rule": s["collision_penalty_rule"] is not None,
            "version": s["version"],
            "status": s["status"],
            "effective_date": s["effective_date"],
            "change_reason": s["change_reason"],
        }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
def canonical_json(document: Any) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


class Registry:
    """Validated, immutable view of one registry document."""

    def __init__(self, document: Mapping[str, Any]):
        doc = copy.deepcopy(dict(document))
        errors = validate_document(doc)
        if errors:
            raise RegistryValidationError(errors)
        self._document = doc
        self._parameters = tuple(Parameter(p) for p in doc["parameters"])
        self._by_id = {p.parameter_id: p for p in self._parameters}
        self._hash = hashlib.sha256(canonical_json(doc).encode("utf-8")).hexdigest()

    # --- identity ---------------------------------------------------------------
    @property
    def registry_version(self) -> str:
        return self._document["registry_version"]

    @property
    def config_version(self) -> str:
        """The configuration version stamped on every relationship (``threshold_version``)."""
        return self._document["config_version"]

    @property
    def registry_hash(self) -> str:
        """SHA-256 over the canonical JSON of the whole document (incl. disabled parameters)."""
        return self._hash

    @property
    def calibration_status(self) -> str:
        return self._document["calibration"]["status"]

    @property
    def is_provisional(self) -> bool:
        return self.calibration_status != "CALIBRATED"

    # --- sections ---------------------------------------------------------------
    @property
    def thresholds(self) -> Mapping[str, Any]:
        return self._document["thresholds"]

    @property
    def t_high(self) -> float:
        return float(self._document["thresholds"]["T_HIGH"]["value"])

    @property
    def t_review(self) -> float:
        return float(self._document["thresholds"]["T_REVIEW"]["value"])

    @property
    def score_model(self) -> Mapping[str, Any]:
        return self._document["score_model"]

    @property
    def candidate_generation(self) -> Mapping[str, Any]:
        return self._document["candidate_generation"]

    @property
    def reference_data(self) -> Mapping[str, Any]:
        return self._document["reference_data"]

    # --- lookup -----------------------------------------------------------------
    @property
    def parameters(self) -> tuple[Parameter, ...]:
        """All parameters, enabled or not, in registry order."""
        return self._parameters

    def get(self, parameter_id: str) -> Parameter:
        try:
            return self._by_id[parameter_id]
        except KeyError:
            raise UnknownParameterError(f"unknown parameter_id {parameter_id!r}") from None

    def find(self, parameter_id: str) -> Parameter | None:
        return self._by_id.get(parameter_id)

    def __contains__(self, parameter_id: object) -> bool:
        return parameter_id in self._by_id

    def __len__(self) -> int:
        return len(self._parameters)

    # --- filtering --------------------------------------------------------------
    def filter(
        self,
        *,
        relationship_class: str | None = None,
        relation_type: str | None = None,
        source_type: str | None = None,
        family: str | None = None,
        role: str | None = None,
        enabled_only: bool = True,
    ) -> list[Parameter]:
        """Parameters matching every given criterion, in registry order.

        ``relationship_class`` is PRIMARY or SECONDARY; ``relation_type`` is a pair
        kind such as ``MAIL-NETWORK``; ``source_type`` is an event source such as
        ``zeek``.
        """
        if relationship_class is not None and relationship_class not in V.RELATIONSHIP_CLASSES:
            raise ValueError(f"unknown relationship_class {relationship_class!r}")
        if relation_type is not None and relation_type not in V.all_pair_kinds():
            raise ValueError(f"unknown relation_type {relation_type!r}")
        out = []
        for p in self._parameters:
            if enabled_only and not p.enabled:
                continue
            if relationship_class is not None and p.relationship_class != relationship_class:
                continue
            if relation_type is not None and not p.applies_to_pair_kind(relation_type):
                continue
            if source_type is not None and not p.applies_to_source(source_type):
                continue
            if family is not None and p.family != family:
                continue
            if role is not None and p.role != role:
                continue
            out.append(p)
        return out

    def for_pair(
        self, source_a: str | None, source_b: str | None, *, relationship_class: str | None = None
    ) -> list[Parameter]:
        """Enabled parameters that can be evaluated for a pair of event sources."""
        return [
            p for p in self._parameters
            if p.enabled
            and (relationship_class is None or p.relationship_class == relationship_class)
            and p.applies_to_pair(source_a, source_b)
        ]

    def count_enabled(self, **criteria: Any) -> int:
        criteria.pop("enabled_only", None)
        return len(self.filter(enabled_only=True, **criteria))

    # --- description / export ---------------------------------------------------
    def describe(self, *, include_parameters: bool = True) -> dict[str, Any]:
        """Counts and configuration for ``GET /correlation/registry``.

        Every number is derived from the loaded document; nothing is typed in.
        """
        enabled = [p for p in self._parameters if p.enabled]

        def tally(keyfunc: Any) -> dict[str, int]:
            out: dict[str, int] = {}
            for p in enabled:
                key = keyfunc(p)
                out[key] = out.get(key, 0) + 1
            return dict(sorted(out.items()))

        by_pair_kind = {k: len(self.filter(relation_type=k)) for k in V.all_pair_kinds()}
        by_source = {s: len(self.filter(source_type=s)) for s in V.KNOWN_EVENT_SOURCES}
        by_class_and_pair = {
            cls: {k: len(self.filter(relationship_class=cls, relation_type=k)) for k in V.all_pair_kinds()}
            for cls in V.RELATIONSHIP_CLASSES
        }
        doc = self._document
        description: dict[str, Any] = {
            "registry_version": self.registry_version,
            "config_version": self.config_version,
            "registry_hash": self.registry_hash,
            "schema_version": doc["schema_version"],
            "effective_date": doc["effective_date"],
            "change_reason": doc["change_reason"],
            "calibration": copy.deepcopy(doc["calibration"]),
            "provisional": self.is_provisional,
            "thresholds": copy.deepcopy(doc["thresholds"]),
            "score_model": copy.deepcopy(doc["score_model"]),
            "candidate_generation": copy.deepcopy(doc["candidate_generation"]),
            "counts": {
                "total_registered": len(self._parameters),
                "enabled": len(enabled),
                "disabled": len(self._parameters) - len(enabled),
                "enabled_by_relationship_class": tally(lambda p: p.relationship_class),
                "enabled_by_role": tally(lambda p: p.role),
                "enabled_by_family": tally(lambda p: p.family),
                "enabled_by_pair_kind": by_pair_kind,
                "enabled_by_relationship_class_and_pair_kind": by_class_and_pair,
                "enabled_by_source_type": by_source,
            },
            "notice": (
                "All weights and thresholds are PROVISIONAL until calibrated on a representative "
                "labelled dataset. A score is an association strength, not proof."
                if self.is_provisional else
                "Weights and thresholds were calibrated; see calibration details."
            ),
        }
        if include_parameters:
            description["parameters"] = [p.summary() for p in self._parameters]
        return description

    def export(self) -> dict[str, Any]:
        """The full validated document (round-trips through ``Registry(...)``)."""
        return copy.deepcopy(self._document)

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self._document, indent=indent, ensure_ascii=True, allow_nan=False)

    def __repr__(self) -> str:
        return f"Registry({self.registry_version!r}, enabled={self.count_enabled()}, hash={self.registry_hash[:12]})"


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------
def _scan_registry_files(directory: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for path in sorted(directory.glob(REGISTRY_FILE_GLOB)):
        try:
            with path.open(encoding="utf-8") as fh:
                version = json.load(fh).get("registry_version")
        except (OSError, ValueError, AttributeError):
            continue
        if isinstance(version, str):
            found[version] = path
    return found


def available_versions(directory: Path | None = None) -> list[str]:
    return sorted(_scan_registry_files(directory or PACKAGE_DIR))


def load_registry(version: str | None = None, *, directory: Path | None = None) -> Registry:
    """Load a registry by version.

    ``version`` is the document's ``registry_version`` (e.g. ``corr-registry-v1``)
    or its file tag (``v1`` for ``registry_v1.json``). ``None`` loads the default.
    The version string is only ever matched against scanned files, never used to
    build a path, so it cannot escape the registry directory.
    """
    wanted = DEFAULT_REGISTRY_VERSION if version is None else version
    if not isinstance(wanted, str) or not _VERSION_TOKEN.fullmatch(wanted):
        raise RegistryVersionError(f"malformed registry version {version!r}")
    files = _scan_registry_files(directory or PACKAGE_DIR)
    path = files.get(wanted)
    if path is None:
        for candidate in files.values():
            if candidate.name == f"registry_{wanted}.json":
                path = candidate
                break
    if path is None:
        raise RegistryVersionError(
            f"unknown registry version {version!r}; available: {sorted(files)}"
        )
    return load_registry_from_path(path)


def load_registry_from_path(path: str | Path) -> Registry:
    try:
        with Path(path).open(encoding="utf-8") as fh:
            document = json.load(fh, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise RegistryValidationError([f"{path}: not valid JSON: {exc}"]) from exc
    return Registry(document)


def load_registry_from_dict(document: Mapping[str, Any]) -> Registry:
    return Registry(document)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name} is not allowed in a registry")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _is_iso_date(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def validate_document(doc: Any) -> list[str]:
    """Return every validation problem in ``doc`` (empty list = valid)."""
    errors: list[str] = []
    if not isinstance(doc, dict):
        return ["registry document must be a JSON object"]

    for key in TOP_LEVEL_REQUIRED_KEYS:
        if key not in doc:
            errors.append(f"missing top-level key {key!r}")
    if errors:
        return errors

    if doc["schema_version"] not in SUPPORTED_SCHEMA_VERSIONS:
        errors.append(f"unsupported schema_version {doc['schema_version']!r}")
    for key in ("registry_version", "config_version"):
        if not isinstance(doc[key], str) or not _VERSION_TOKEN.fullmatch(doc[key]):
            errors.append(f"{key} must be a short token of letters, digits, '.', '_' or '-'")
    if not _is_iso_date(doc["effective_date"]):
        errors.append("effective_date must be an ISO date (YYYY-MM-DD)")
    if not isinstance(doc["change_reason"], str) or not doc["change_reason"].strip():
        errors.append("change_reason must be a non-empty string")

    errors += _validate_calibration(doc["calibration"])
    provisional = isinstance(doc["calibration"], dict) and doc["calibration"].get("status") != "CALIBRATED"
    errors += _validate_score_model(doc["score_model"])
    errors += _validate_thresholds(doc["thresholds"], doc["score_model"], provisional)
    errors += _validate_candidate_generation(doc["candidate_generation"])
    errors += _validate_reference_data(doc["reference_data"])
    errors += _validate_parameters(doc["parameters"], doc["reference_data"], provisional)
    return errors


def _validate_calibration(cal: Any) -> list[str]:
    if not isinstance(cal, dict):
        return ["calibration must be an object"]
    errs = []
    if cal.get("status") not in V.CALIBRATION_STATUSES:
        errs.append(f"calibration.status must be one of {V.CALIBRATION_STATUSES}")
    if cal.get("status") == "CALIBRATED" and not cal.get("evaluation_ref"):
        errs.append("a CALIBRATED registry must cite calibration.evaluation_ref")
    return errs


def _validate_score_model(sm: Any) -> list[str]:
    if not isinstance(sm, dict):
        return ["score_model must be an object"]
    errs = []
    lo, hi = sm.get("clamp_min"), sm.get("clamp_max")
    if not (_is_number(lo) and _is_number(hi) and lo < hi):
        errs.append("score_model needs numeric clamp_min < clamp_max")
    return errs


def _validate_thresholds(th: Any, sm: Any, provisional: bool) -> list[str]:
    if not isinstance(th, dict):
        return ["thresholds must be an object"]
    errs: list[str] = []
    values: dict[str, float] = {}
    for name in ("T_HIGH", "T_REVIEW"):
        entry = th.get(name)
        if not isinstance(entry, dict) or not _is_number(entry.get("value")):
            errs.append(f"thresholds.{name} needs a numeric 'value'")
            continue
        if entry.get("status") not in V.CALIBRATION_STATUSES:
            errs.append(f"thresholds.{name}.status must be one of {V.CALIBRATION_STATUSES}")
        elif provisional and entry["status"] != "PROVISIONAL":
            errs.append(f"thresholds.{name} is CALIBRATED but the registry calibration is PROVISIONAL")
        values[name] = float(entry["value"])
    if len(values) == 2:
        if not values["T_REVIEW"] < values["T_HIGH"]:
            errs.append("thresholds require T_REVIEW < T_HIGH")
        if isinstance(sm, dict) and _is_number(sm.get("clamp_min")) and _is_number(sm.get("clamp_max")):
            if not (sm["clamp_min"] < values["T_REVIEW"] and values["T_HIGH"] <= sm["clamp_max"]):
                errs.append("thresholds must lie inside the score_model clamp range")
    return errs


def _validate_candidate_generation(cg: Any) -> list[str]:
    if not isinstance(cg, dict):
        return ["candidate_generation must be an object"]
    errs = []
    windows = cg.get("windows_seconds")
    if not isinstance(windows, dict) or "default" not in windows:
        errs.append("candidate_generation.windows_seconds needs a 'default' window")
    else:
        for name, value in windows.items():
            if not (_is_number(value) and value > 0):
                errs.append(f"candidate_generation.windows_seconds.{name} must be a positive number")
    hubs = cg.get("hub_thresholds")
    if not isinstance(hubs, dict):
        errs.append("candidate_generation.hub_thresholds must be an object")
    else:
        for name, value in hubs.items():
            if name not in V.HUB_COUNTERS:
                errs.append(f"candidate_generation.hub_thresholds has unknown counter {name!r}")
            if not (isinstance(value, int) and not isinstance(value, bool) and value >= 1):
                errs.append(f"candidate_generation.hub_thresholds.{name} must be an integer >= 1")
    indexes = cg.get("indexes")
    if not isinstance(indexes, list) or not indexes:
        errs.append("candidate_generation.indexes must be a non-empty list")
    else:
        for name in indexes:
            if name not in V.CANDIDATE_INDEXES:
                errs.append(f"candidate_generation.indexes has unknown index {name!r}")
        if len(set(indexes)) != len(indexes):
            errs.append("candidate_generation.indexes contains duplicates")
    mb = cg.get("max_bucket_size")
    if not (isinstance(mb, int) and not isinstance(mb, bool) and mb >= 2):
        errs.append("candidate_generation.max_bucket_size must be an integer >= 2")
    return errs


def _validate_reference_data(ref: Any) -> list[str]:
    if not isinstance(ref, dict):
        return ["reference_data must be an object"]
    errs = []
    pairs = ref.get("ordered_action_pairs")
    if not isinstance(pairs, list) or not all(
        isinstance(p, list) and len(p) == 2 and all(isinstance(x, str) and x for x in p) for p in pairs
    ):
        errs.append("reference_data.ordered_action_pairs must be a list of [earlier, later] string pairs")
    common = ref.get("common_values")
    if not isinstance(common, dict):
        errs.append("reference_data.common_values must be an object")
    else:
        for name, values in common.items():
            if name not in V.COMMON_VALUE_LISTS:
                errs.append(f"reference_data.common_values has unknown list {name!r}")
            elif not isinstance(values, list) or not all(isinstance(x, str) for x in values):
                errs.append(f"reference_data.common_values.{name} must be a list of strings")
    groups = ref.get("alias_groups")
    if not isinstance(groups, list) or not all(
        isinstance(g, dict) and isinstance(g.get("group_id"), str) and isinstance(g.get("members"), list)
        and all(isinstance(m, str) and m for m in g["members"]) and len(g["members"]) >= 2
        for g in groups
    ):
        errs.append("reference_data.alias_groups must be a list of {group_id, members[>=2]} objects")
    return errs


def _validate_parameters(params: Any, ref: Any, provisional: bool) -> list[str]:
    if not isinstance(params, list) or not params:
        return ["parameters must be a non-empty list"]
    errs: list[str] = []
    seen: dict[str, int] = {}
    for i, p in enumerate(params):
        label = f"parameters[{i}]"
        if isinstance(p, dict) and isinstance(p.get("parameter_id"), str):
            label = f"parameter {p['parameter_id']}"
            seen[p["parameter_id"]] = seen.get(p["parameter_id"], 0) + 1
    for pid, n in sorted(seen.items()):
        if n > 1:
            errs.append(f"duplicate parameter_id {pid!r} ({n} times)")

    by_id = {p["parameter_id"]: p for p in params if isinstance(p, dict) and isinstance(p.get("parameter_id"), str)}
    for i, p in enumerate(params):
        label = f"parameters[{i}]"
        if isinstance(p, dict) and isinstance(p.get("parameter_id"), str):
            label = f"parameter {p['parameter_id']}"
        errs += [f"{label}: {e}" for e in _validate_parameter(p, by_id, ref, provisional)]
    return errs


def _validate_parameter(p: Any, by_id: Mapping[str, Any], ref: Any, provisional: bool) -> list[str]:
    if not isinstance(p, dict):
        return ["must be an object"]
    errs: list[str] = []
    for key in PARAMETER_REQUIRED_KEYS:
        if key not in p:
            errs.append(f"missing field {key!r}")
    if errs:
        return errs
    unknown = sorted(set(p) - set(PARAMETER_REQUIRED_KEYS))
    if unknown:
        errs.append(f"unknown field(s) {unknown}")

    if not isinstance(p["parameter_id"], str) or not _PARAM_ID.fullmatch(p["parameter_id"]):
        errs.append("parameter_id must be UPPER_SNAKE_CASE (3-64 chars)")
    for key in ("display_name", "description", "version", "change_reason"):
        if not isinstance(p[key], str) or not p[key].strip():
            errs.append(f"{key} must be a non-empty string")
    if p["family"] not in V.FAMILIES:
        errs.append(f"family must be one of {V.FAMILIES}")
    if p["role"] not in V.ROLES:
        errs.append(f"role must be one of {V.ROLES}")
    if p["direction"] not in V.DIRECTIONS:
        errs.append(f"direction must be one of {V.DIRECTIONS}")
    if p["status"] not in V.STATUSES:
        errs.append(f"status must be one of {V.STATUSES}")
    if not _is_iso_date(p["effective_date"]):
        errs.append("effective_date must be an ISO date")
    if p["role"] == "CONTRADICTION" and p["direction"] != "WEAKENS":
        errs.append("a CONTRADICTION parameter must have direction WEAKENS")
    if p["role"] in ("ANCHOR", "FEATURE", "RELIABILITY_FACTOR") and p["direction"] != "SUPPORTS":
        errs.append(f"a {p['role']} parameter must have direction SUPPORTS")

    # relation types and sources
    rt = p["relation_type"]
    if not isinstance(rt, list) or not rt or not all(isinstance(x, str) and V.valid_relation_pattern(x) for x in rt):
        errs.append("relation_type must be a non-empty list of ANY / <CAT>-<CAT> / <CAT>-* patterns")
    srcs = p["applies_to_sources"]
    if not isinstance(srcs, list) or not srcs or not all(x == "*" or x in V.KNOWN_EVENT_SOURCES for x in srcs):
        errs.append("applies_to_sources must be ['*'] or a list of known event sources")

    # source fields
    sf = p["source_fields"]
    if not isinstance(sf, list) or not sf or not all(isinstance(x, str) for x in sf):
        errs.append("source_fields must be a non-empty list of field names")
    else:
        bad = sorted(set(sf) - V.FIELD_NAMES)
        if bad:
            errs.append(f"source_fields contains unknown field(s) {bad}")

    errs += _validate_extraction(p)
    errs += _validate_normalisation(p)

    # weight
    w = p["weight"]
    if p["role"] in ("FEATURE", "CONTRADICTION"):
        if not (_is_number(w) and 0.0 <= w <= 1.0):
            errs.append("weight must be a number in [0, 1] for FEATURE and CONTRADICTION parameters")
    elif w is not None:
        errs.append(f"weight must be null for {p['role']} parameters")
    if p["weight_status"] not in V.CALIBRATION_STATUSES:
        errs.append(f"weight_status must be one of {V.CALIBRATION_STATUSES}")
    elif provisional and p["weight_status"] != "PROVISIONAL":
        errs.append("weight_status is CALIBRATED but the registry calibration is PROVISIONAL")

    errs += _validate_reliability(p, by_id)
    errs += _validate_missing(p)
    errs += _validate_collision(p, ref)
    errs += _validate_fixtures(p)
    return errs


def _validate_extraction(p: Mapping[str, Any]) -> list[str]:
    em = p["extraction_method"]
    if not isinstance(em, dict) or em.get("method") not in V.EXTRACTION_METHODS:
        return [f"extraction_method.method must be one of the known methods"]
    errs: list[str] = []
    method = em["method"]
    if method == "FIELD_QUALITY_MAP":
        m = em.get("map")
        if not isinstance(m, dict) or not m or not all(_is_number(v) and 0.0 <= v <= 1.0 for v in m.values()):
            errs.append("FIELD_QUALITY_MAP needs a 'map' of value -> factor in [0, 1]")
        d = em.get("default")
        if d is not None and not (_is_number(d) and 0.0 <= d <= 1.0):
            errs.append("FIELD_QUALITY_MAP default must be null or in [0, 1]")
        blocks = em.get("block_values", [])
        if not isinstance(blocks, list) or not all(isinstance(x, str) for x in blocks):
            errs.append("block_values must be a list of strings")
    if method == "CONFLICT_CHECK":
        checks = em.get("checks")
        if not (isinstance(checks, list) and checks):
            errs.append("CONFLICT_CHECK needs a non-empty 'checks' list")
        else:
            for n, check in enumerate(checks):
                if not (isinstance(check, dict) and isinstance(check.get("key_fields"), list) and check["key_fields"]
                        and isinstance(check.get("fact_fields"), list) and check["fact_fields"]):
                    errs.append(f"CONFLICT_CHECK checks[{n}] needs non-empty key_fields and fact_fields")
                    continue
                bad = sorted((set(check["key_fields"]) | set(check["fact_fields"])) - V.FIELD_NAMES)
                if bad:
                    errs.append(f"CONFLICT_CHECK checks[{n}] refers to unknown field(s) {bad}")
                tol = check.get("tolerance_seconds")
                if tol is not None and not (_is_number(tol) and tol >= 0):
                    errs.append(f"CONFLICT_CHECK checks[{n}].tolerance_seconds must be >= 0")
    if method in ("SET_INTERSECTION",):
        pairs = em.get("pairs")
        if pairs is not None and not (
            isinstance(pairs, list) and pairs and all(
                isinstance(x, list) and len(x) == 2 and set(x) <= V.FIELD_NAMES for x in pairs)
        ):
            errs.append("SET_INTERSECTION pairs must be a list of [fieldA, fieldB] known fields")
    if method == "CLOCK_UNCERTAINTY" and not (_is_number(em.get("window_seconds")) and em["window_seconds"] > 0):
        errs.append("CLOCK_UNCERTAINTY needs a positive window_seconds")
    if method == "ANCHOR_SCOPED_EXACT":
        scope = em.get("scope_fields")
        if not (isinstance(scope, list) and scope and set(scope) <= V.FIELD_NAMES):
            errs.append("ANCHOR_SCOPED_EXACT needs scope_fields drawn from known fields")
        if em.get("scope_mode", "ALL") not in V.SCOPE_MODES:
            errs.append(f"ANCHOR_SCOPED_EXACT scope_mode must be one of {V.SCOPE_MODES}")
    if method.startswith("ANCHOR_") and p["role"] != "ANCHOR":
        errs.append("ANCHOR_* extraction methods may only be used by ANCHOR parameters")
    if p["role"] == "ANCHOR" and not method.startswith("ANCHOR_"):
        errs.append("an ANCHOR parameter must use an ANCHOR_* extraction method")
    return errs


def _validate_normalisation(p: Mapping[str, Any]) -> list[str]:
    nr = p["normalisation_rule"]
    if not isinstance(nr, dict) or nr.get("kind") not in V.NORMALISATION_KINDS:
        return ["normalisation_rule.kind must be one of the known kinds"]
    errs = []
    if nr["kind"] == "LINEAR_DECAY" and not (_is_number(nr.get("window_seconds")) and nr["window_seconds"] > 0):
        errs.append("LINEAR_DECAY needs a positive window_seconds")
    if nr["kind"] == "UNIT_RESCALE" and not (_is_number(nr.get("min_factor")) and 0.0 <= nr["min_factor"] <= 1.0):
        errs.append("UNIT_RESCALE needs min_factor in [0, 1]")
    if nr["kind"] == "UNIT_FLOOR" and not (_is_number(nr.get("floor")) and 0.0 <= nr["floor"] < 1.0):
        errs.append("UNIT_FLOOR needs floor in [0, 1)")
    return errs


def _validate_reliability(p: Mapping[str, Any], by_id: Mapping[str, Any]) -> list[str]:
    rr = p["reliability_rule"]
    if p["role"] in ("ANCHOR", "RELIABILITY_FACTOR", "CONTRADICTION"):
        return [] if rr is None else [f"reliability_rule must be null for {p['role']} parameters"]
    if not isinstance(rr, dict):
        return ["a FEATURE needs a reliability_rule object"]
    errs = []
    if rr.get("combine") not in V.COMBINE_RULES:
        errs.append(f"reliability_rule.combine must be one of {V.COMBINE_RULES}")
    factors = rr.get("factors")
    if not isinstance(factors, list) or not all(isinstance(f, str) for f in factors):
        errs.append("reliability_rule.factors must be a list of parameter_ids")
    else:
        for f in factors:
            target = by_id.get(f)
            if target is None:
                errs.append(f"reliability_rule refers to unknown parameter {f!r}")
            elif target.get("role") != "RELIABILITY_FACTOR":
                errs.append(f"reliability_rule factor {f!r} is not a RELIABILITY_FACTOR")
        if len(set(factors)) != len(factors):
            errs.append("reliability_rule.factors contains duplicates")
    floor = rr.get("floor", 0.0)
    if not (_is_number(floor) and 0.0 <= floor <= 1.0):
        errs.append("reliability_rule.floor must be in [0, 1]")
    return errs


def _validate_missing(p: Mapping[str, Any]) -> list[str]:
    mv = p["missing_value_policy"]
    if not isinstance(mv, dict) or mv.get("policy") not in V.MISSING_VALUE_POLICIES:
        return [f"missing_value_policy.policy must be one of {V.MISSING_VALUE_POLICIES}"]
    if mv["policy"] == "EXPLICIT_PENALTY":
        pen = mv.get("penalty")
        if not (_is_number(pen) and 0.0 < pen <= 1.0):
            return ["EXPLICIT_PENALTY needs a penalty in (0, 1]"]
    return []


def _validate_collision(p: Mapping[str, Any], ref: Any) -> list[str]:
    cr = p["collision_penalty_rule"]
    if cr is None:
        return []
    if p["role"] != "FEATURE":
        return ["only FEATURE parameters may carry a collision_penalty_rule"]
    if not isinstance(cr, dict) or cr.get("kind") not in V.COLLISION_KINDS:
        return [f"collision_penalty_rule.kind must be one of {sorted(V.COLLISION_KINDS)}"]
    errs = []
    if cr["kind"] == "HUB_COUNT":
        if cr.get("counter") not in V.HUB_COUNTERS:
            errs.append(f"HUB_COUNT counter must be one of {sorted(V.HUB_COUNTERS)}")
    if cr["kind"] == "COMMON_VALUE":
        lst = cr.get("list")
        if lst not in V.COMMON_VALUE_LISTS:
            errs.append(f"COMMON_VALUE list must be one of {sorted(V.COMMON_VALUE_LISTS)}")
        elif isinstance(ref, dict) and lst not in (ref.get("common_values") or {}):
            errs.append(f"COMMON_VALUE list {lst!r} is not defined in reference_data.common_values")
        pf = cr.get("penalty_factor")
        if not (_is_number(pf) and 0.0 < pf <= 1.0):
            errs.append("COMMON_VALUE needs penalty_factor in (0, 1]")
    return errs


def _validate_fixtures(p: Mapping[str, Any]) -> list[str]:
    fx = p["fixtures"]
    if not isinstance(fx, dict):
        return ["fixtures must be an object with 'positive' and 'negative'"]
    errs = []
    if set(fx) != {"positive", "negative"}:
        errs.append("fixtures must contain exactly 'positive' and 'negative'")
    allowed_status = V.ANCHOR_OUTCOMES if p["role"] == "ANCHOR" else V.EVALUATION_STATUSES
    for kind in ("positive", "negative"):
        case = fx.get(kind)
        if not isinstance(case, dict):
            errs.append(f"fixtures.{kind} is required")
            continue
        extra = sorted(set(case) - V.FIXTURE_CASE_KEYS)
        if extra:
            errs.append(f"fixtures.{kind} has unknown key(s) {extra}")
        events = case.get("events")
        if not (isinstance(events, list) and len(events) == 2 and all(isinstance(e, dict) for e in events)):
            errs.append(f"fixtures.{kind}.events must be a list of two event objects")
        else:
            sources = []
            for n, e in enumerate(events):
                src = e.get("source")
                if src not in V.KNOWN_EVENT_SOURCES:
                    errs.append(f"fixtures.{kind}.events[{n}].source must be a known event source")
                if not isinstance(e.get("timestamp"), str) or not e.get("timestamp"):
                    errs.append(f"fixtures.{kind}.events[{n}] needs a timestamp")
                sources.append(src)
            if all(s in V.KNOWN_EVENT_SOURCES for s in sources):
                if not (isinstance(p.get("relation_type"), list) and isinstance(p.get("applies_to_sources"), list)):
                    pass
                else:
                    kind_of_pair = V.pair_kind(sources[0], sources[1])
                    allowed_src = p["applies_to_sources"]
                    if not V.relation_type_matches(p["relation_type"], kind_of_pair):
                        errs.append(f"fixtures.{kind} events form a {kind_of_pair} pair that the parameter's "
                                    "relation_type does not cover")
                    if any("*" not in allowed_src and s not in allowed_src for s in sources):
                        errs.append(f"fixtures.{kind} uses a source outside applies_to_sources")
        expect = case.get("expect")
        if not isinstance(expect, dict) or not expect:
            errs.append(f"fixtures.{kind}.expect must be a non-empty object")
        else:
            bad = sorted(set(expect) - V.FIXTURE_EXPECT_KEYS)
            if bad:
                errs.append(f"fixtures.{kind}.expect has unknown key(s) {bad}")
            for key in ("value", "min", "max"):
                if key in expect and not (_is_number(expect[key]) and 0.0 <= expect[key] <= 1.0):
                    errs.append(f"fixtures.{kind}.expect.{key} must be a number in [0, 1]")
            if "status" in expect and expect["status"] not in allowed_status:
                errs.append(f"fixtures.{kind}.expect.status must be one of {allowed_status}")
            if p["role"] == "ANCHOR" and "status" not in expect:
                errs.append(f"fixtures.{kind}.expect needs a status for an ANCHOR parameter")
        if not (isinstance(case.get("label"), str) and case["label"]):
            errs.append(f"fixtures.{kind}.label must describe the case")
        if "source_clocks" in case and not isinstance(case["source_clocks"], dict):
            errs.append(f"fixtures.{kind}.source_clocks must be an object")
        if "reference_data" in case and not isinstance(case["reference_data"], dict):
            errs.append(f"fixtures.{kind}.reference_data must be an object")
    return errs


def iter_fixtures(registry: Registry) -> Iterable[tuple[Parameter, str, Mapping[str, Any]]]:
    """Yield ``(parameter, 'positive'|'negative', fixture)`` for every parameter."""
    for p in registry.parameters:
        for kind in ("positive", "negative"):
            yield p, kind, p.spec["fixtures"][kind]
