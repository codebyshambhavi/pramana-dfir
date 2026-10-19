"""Timestamp normalization shared by evidence parsers."""
from datetime import datetime, timezone


def normalize_timestamp(value: str) -> str:
    """Return an ISO 8601 timestamp normalized to UTC with a trailing Z."""
    timestamp = value.strip()
    if timestamp.endswith("Z"):
        timestamp = timestamp[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise ValueError(f"Invalid ISO 8601 timestamp: {value!r}") from exc

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")