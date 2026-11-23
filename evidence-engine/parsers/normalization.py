"""Reusable normalisation helpers for Role 1 parsers."""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Iterable


EMAIL_PATTERN = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
IP_PATTERN = re.compile(r"(?<![\d.:])(?:\d{1,3}\.){3}\d{1,3}(?![\d.:])")
DOMAIN_PATTERN = re.compile(r"(?i)(?<![@\w])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")


def utc_timestamp(value: datetime | str) -> tuple[str, str]:
    """Return (RFC3339 UTC string, timezone assumption). Missing values are not accepted."""
    if isinstance(value, datetime):
        assumption = "explicit_offset" if value.tzinfo is not None else "assumed_utc"
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("Missing timestamp")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ValueError(f"Invalid timestamp: {value}") from exc
        assumption = "explicit_offset" if dt.tzinfo is not None else "assumed_utc"
        dt = dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
    else:
        raise ValueError("Missing timestamp")
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"), assumption


def stable_event_id(prefix: str, case_id: str, evidence_id: str, locator: str) -> str:
    digest = hashlib.sha256(f"{case_id}|{evidence_id}|{locator}".encode("utf-8")).hexdigest()[:12]
    return f"{prefix}-{digest}"


def extract_entities(*values: Any) -> list[dict[str, Any]]:
    """Extract conservative email, IPv4 and domain entities."""
    text = "\n".join(str(value) for value in values if value is not None)
    entities: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for pattern, entity_type, confidence in (
        (EMAIL_PATTERN, "email", 0.99),
        (IP_PATTERN, "ip", 0.95),
        (DOMAIN_PATTERN, "domain", 0.90),
    ):
        for match in pattern.findall(text):
            value = match.lower() if entity_type != "ip" else match
            key = (entity_type, value)
            if key in seen:
                continue
            seen.add(key)
            entities.append({
                "entity_type": entity_type,
                "canonical_value": value,
                "aliases": [match],
                "normalisation_method": "regex",
                "confidence": confidence,
            })
    return entities
