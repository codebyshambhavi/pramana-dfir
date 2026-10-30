"""Timestamp normalization shared by evidence parsers."""
from datetime import datetime, timezone

# How the timezone of a source timestamp was determined (Event v1.1 ``tz_assumption``).
TZ_EXPLICIT_OFFSET = "explicit_offset"  # the source text carried Z or +hh:mm
TZ_ASSUMED_UTC = "assumed_utc"          # the source text was naive; UTC is an assumption
TZ_EPOCH_UTC = "epoch_utc"              # the source is a Unix epoch (UTC by definition)


def normalize_timestamp_with_basis(value: str) -> tuple[str, str]:
    """Return ``(iso_utc_with_Z, tz_assumption)`` for an ISO 8601 timestamp.

    ``tz_assumption`` is ``explicit_offset`` when the input carried an offset
    (or ``Z``) and ``assumed_utc`` when it was naive. The raw text is never
    altered by this function; callers keep it in ``Event.raw``.
    """
    timestamp = value.strip()
    if timestamp.endswith("Z"):
        timestamp = timestamp[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise ValueError(f"Invalid ISO 8601 timestamp: {value!r}") from exc

    if parsed.tzinfo is None:
        basis = TZ_ASSUMED_UTC
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        basis = TZ_EXPLICIT_OFFSET
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), basis


def normalize_timestamp(value: str) -> str:
    """Return an ISO 8601 timestamp normalized to UTC with a trailing Z."""
    return normalize_timestamp_with_basis(value)[0]
