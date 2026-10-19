"""Role 2 configuration.

Plain constants for the rules that later R2-* modules will implement.
Nothing here performs any analysis, and the module has no third-party
dependencies.

Timezone
--------
``get_timezone()`` returns the timezone used for *wall-clock* rules such as
"odd hours". The default is UTC because the current backend tests expect UTC
behaviour. Override with the ``PRAMANA_INTEL_TIMEZONE`` environment variable
(an IANA name such as ``Asia/Kolkata``). Non-UTC names need the system tz
database (or the ``tzdata`` package) to be present.

The timezone is NOT used to interpret naive event timestamps. Those are always
treated as UTC (see ``common.parse_timestamp``).
"""
from __future__ import annotations

import os
from datetime import timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# --- timezone ---------------------------------------------------------------
TIMEZONE_ENV_VAR = "PRAMANA_INTEL_TIMEZONE"
DEFAULT_TIMEZONE_NAME = "UTC"

# --- time windows -----------------------------------------------------------
# Max gap between events from different sources for them to be correlated.
DEFAULT_CORRELATION_WINDOW = timedelta(minutes=10)
# Max gap between an archive being created and an upload of it.
ARCHIVE_UPLOAD_WINDOW = timedelta(minutes=30)

# --- odd hours (wall-clock hours in the configured timezone) ----------------
# Half-open range [start, end). If start > end the range wraps midnight
# (e.g. start=22, end=5 means 22:00-04:59).
ODD_HOUR_START = 0
ODD_HOUR_END = 5

# --- thresholds reserved for later modules (unused in R2-1) -----------------
# Maximum plausible travel speed, used for location-vs-time checks.
MAX_PLAUSIBLE_SPEED_KMH = 900.0
# Findings below this confidence are still emitted but never auto-trusted.
MIN_REPORTABLE_CONFIDENCE = 0.1


def get_timezone() -> tzinfo:
    """Return the configured timezone (default UTC).

    Raises ``ValueError`` if the configured name is not a known IANA zone.
    """
    name = os.environ.get(TIMEZONE_ENV_VAR, DEFAULT_TIMEZONE_NAME).strip() or DEFAULT_TIMEZONE_NAME
    if name.upper() == "UTC":
        return timezone.utc
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"Unknown timezone {name!r} in {TIMEZONE_ENV_VAR}") from exc
