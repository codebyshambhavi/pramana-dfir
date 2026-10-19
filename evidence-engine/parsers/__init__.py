"""Role 1 evidence dispatcher.

The dispatcher computes the evidence hash, selects the narrow parser that matches
an evidence file, and returns schema-shaped Event dictionaries. It deliberately
avoids a generic fallback parser: an unsupported or ambiguous file is rejected.
"""
from __future__ import annotations

import csv
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator, FormatChecker

from intake.hashing import sha256_file
from . import browser_csv, chat_json, image_meta, log_csv, pcap


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _PROJECT_ROOT / "contracts" / "event.schema.json"

_DATE_TIME_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def _is_rfc3339_datetime(value: object) -> bool:
    """Check an RFC 3339 date-time with an explicit timezone offset."""
    if not isinstance(value, str) or not _DATE_TIME_PATTERN.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


_DATE_TIME_FORMAT_CHECKER = FormatChecker()
_DATE_TIME_FORMAT_CHECKER.checks("date-time")(_is_rfc3339_datetime)


def _load_event_validator() -> Draft202012Validator | None:
    """Load the repository Event schema when available."""
    if not _SCHEMA_PATH.is_file():
        return None
    try:
        schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
        return Draft202012Validator(schema, format_checker=_DATE_TIME_FORMAT_CHECKER)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to load Event schema: {_SCHEMA_PATH}: {exc}") from exc


def _csv_kind(path: Path) -> str:
    """Classify a CSV by its required header shape, not by filename."""
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            sample = handle.read(8192)
        if not sample.strip():
            raise ValueError("CSV evidence file is empty")
        reader = csv.reader(sample.splitlines())
        headers = {h.strip().lower() for h in next(reader)}
    except (OSError, StopIteration, csv.Error) as exc:
        raise ValueError(f"Cannot inspect CSV evidence '{path.name}': {exc}") from exc

    if {"timestamp", "action", "url"}.issubset(headers):
        return "browser"
    if {"timestamp", "action"}.issubset(headers):
        return "log"
    raise ValueError(
        f"Unsupported CSV evidence '{path.name}': expected browser headers "
        "timestamp, action, url or log headers timestamp, action"
    )


def _select_parser(path: Path) -> tuple[Callable[..., list[dict]], str]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        kind = _csv_kind(path)
        return (browser_csv.parse if kind == "browser" else log_csv.parse), kind
    if suffix == ".json":
        return chat_json.parse, "chat"
    if suffix in {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp", ".bmp"}:
        return image_meta.parse, "image"
    if suffix in {".pcap", ".pcapng"}:
        return pcap.parse, "pcap"
    raise ValueError(
        f"Unsupported evidence format '{suffix or '<no extension>'}' for '{path.name}'. "
        "Supported formats: browser/log CSV, chat JSON, images, PCAP/PCAPNG."
    )


def _validate_events(events: list[dict], validator: Draft202012Validator | None) -> None:
    """Validate returned Events against the repository contract when available."""
    if validator is None:
        return
    errors: list[str] = []
    for index, event in enumerate(events):
        for error in sorted(validator.iter_errors(event), key=lambda e: list(e.path)):
            location = ".".join(str(part) for part in error.path) or "<event>"
            errors.append(f"event[{index}] {location}: {error.message}")
    if errors:
        raise ValueError("Parser produced schema-invalid Events: " + "; ".join(errors))


def parse_evidence(path: str, case_id: str) -> list[dict]:
    """Parse one evidence file into schema-valid Events.

    Evidence IDs are deterministic for standalone parsing: ``EVID-001``. The
    backend's intake layer may replace this with its persisted intake ID. Event
    IDs are namespaced with the source-file hash so events from different
    evidence files cannot collide.
    """
    evidence_path = Path(path)
    if not evidence_path.is_file():
        raise ValueError(f"Evidence file does not exist: {path}")
    if not case_id:
        raise ValueError("case_id must be non-empty")

    parser, _source = _select_parser(evidence_path)
    digest = sha256_file(str(evidence_path))
    evidence_id = "EVID-001"
    events = parser(str(evidence_path), case_id, evidence_id, digest)

    if not isinstance(events, list):
        raise ValueError("Parser returned a non-list result")

    # Preserve each parser's human-readable local ID while making IDs globally
    # unique across evidence files.
    for event in events:
        if not isinstance(event, dict):
            raise ValueError("Parser returned a non-dictionary Event")
        local_id = event.get("event_id")
        if not isinstance(local_id, str) or not local_id:
            raise ValueError("Parser returned an Event without a valid event_id")
        event["event_id"] = f"{digest[:12]}:{local_id}"
        event["case_id"] = case_id
        event["evidence_id"] = evidence_id
        event["sha256"] = digest

    _validate_events(events, _load_event_validator())
    return events
