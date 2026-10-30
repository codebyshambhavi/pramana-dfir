"""Role 3: analysis pipeline glue between the backend and Roles 1 and 2.

Agreed interfaces:
- parse_evidence(path: str, case_id: str) -> list[Event]       (evidence-engine)
- analyze(events: list[Event]) -> list[Finding]                (intelligence)

Execution is deterministic and explicit. There is no fallback parser and no
fallback analyzer: if a parser or the intelligence package cannot run, or if its
output does not satisfy the contracts, the error is raised to the caller. The
pipeline never substitutes weaker logic, never skips non-compliant output and
never synthesizes placeholder events or findings.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import jsonschema

# Resolve repository root to locate JSON schemas and sibling packages.
REPO_ROOT = Path(__file__).resolve().parents[3]
EVENT_SCHEMA_PATH = REPO_ROOT / "contracts" / "event.schema.json"
FINDING_SCHEMA_PATH = REPO_ROOT / "contracts" / "finding.schema.json"

_event_validator: jsonschema.Draft202012Validator | None = None
_finding_validator: jsonschema.Draft202012Validator | None = None


class PipelineError(RuntimeError):
    """The pipeline could not run (missing contract, missing package, bad output).

    Distinct from ``ValueError`` raised by parsers for bad *evidence*: a
    PipelineError means the installation or a contract is broken.
    """


def _load_validator(schema_path: Path) -> jsonschema.Draft202012Validator:
    if not schema_path.is_file():
        raise PipelineError(f"Contract schema is missing: {schema_path}")
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
    except (OSError, json.JSONDecodeError, jsonschema.SchemaError) as exc:
        raise PipelineError(f"Contract schema is unreadable: {schema_path}: {exc}") from exc
    return jsonschema.Draft202012Validator(schema)


def get_event_validator() -> jsonschema.Draft202012Validator:
    global _event_validator
    if _event_validator is None:
        _event_validator = _load_validator(EVENT_SCHEMA_PATH)
    return _event_validator


def get_finding_validator() -> jsonschema.Draft202012Validator:
    global _finding_validator
    if _finding_validator is None:
        _finding_validator = _load_validator(FINDING_SCHEMA_PATH)
    return _finding_validator


def validate_event_dict(event: dict[str, Any]) -> None:
    """Validate an Event against contracts/event.schema.json (raises on failure)."""
    get_event_validator().validate(event)


def validate_finding_dict(finding: dict[str, Any]) -> None:
    """Validate a Finding against contracts/finding.schema.json (raises on failure)."""
    get_finding_validator().validate(finding)


def _ensure_import_paths() -> None:
    """Make the sibling packages importable (backend runs from backend/)."""
    for entry in (REPO_ROOT / "evidence-engine", REPO_ROOT):
        if entry.is_dir() and str(entry) not in sys.path:
            sys.path.insert(0, str(entry))


def execute_parse_evidence(path: str, case_id: str, evidence_id: str, sha256: str) -> list[dict[str, Any]]:
    """Parse one evidence file with the evidence-engine and validate every Event.

    Raises:
        PipelineError: the evidence-engine (or one of its dependencies) cannot
            be imported, or it returned something that is not a list of Events.
        ValueError: the evidence itself is unsupported or malformed (raised by
            the parsers; not retried with any other parser).
        jsonschema.ValidationError: an Event violates contracts/event.schema.json.
    """
    _ensure_import_paths()
    try:
        from parsers import parse_evidence  # type: ignore
    except ImportError as exc:
        raise PipelineError(
            "evidence-engine could not be imported; install dependencies with "
            f"'pip install -r requirements.txt': {exc}"
        ) from exc

    events = parse_evidence(path, case_id)
    if not isinstance(events, list):
        raise PipelineError("evidence-engine parse_evidence() did not return a list")

    for event in events:
        event["case_id"] = case_id
        event["evidence_id"] = evidence_id
        event["sha256"] = sha256
        validate_event_dict(event)
    return events


def execute_analyze(events: list[dict[str, Any]], case_id: str) -> list[dict[str, Any]]:
    """Run the deterministic intelligence pipeline and validate every Finding.

    Raises:
        PipelineError: the intelligence package cannot be imported.
        intelligence.common.IntelligenceError (or subclass): an Event or Finding
            is unusable. Never swallowed and never replaced by a baseline finding.
        jsonschema.ValidationError: a Finding violates contracts/finding.schema.json.
    """
    _ensure_import_paths()
    try:
        from intelligence import analyze  # type: ignore
    except ImportError as exc:
        raise PipelineError(
            "intelligence package could not be imported; install dependencies with "
            f"'pip install -r requirements.txt': {exc}"
        ) from exc

    findings = analyze(events)
    for finding in findings:
        finding["case_id"] = case_id
        validate_finding_dict(finding)
    return findings
