"""Event v1.1 provenance fields shared by every parser.

Event v1.1 adds three OPTIONAL fields; no v1.0 field was removed or renamed:

- ``parser_version``: ``"<parser>@<version>"`` of the code that produced the Event.
- ``tz_assumption``:  how the timestamp's timezone was determined
                      (see ``parsers.timestamps``).
- ``family``:         the artifact family the Event came from (system log,
                      browser history, chat export, network capture, image
                      EXIF). Events of one family from one evidence file are
                      one witness when source independence is judged later.
"""
from __future__ import annotations

from typing import Any

EVENT_SCHEMA_VERSION = "1.1"


def provenance_fields(*, parser: str, version: str, family: str, tz_assumption: str) -> dict[str, Any]:
    """Return the three Event v1.1 optional fields as one dict."""
    for name, value in (("parser", parser), ("version", version), ("family", family), ("tz_assumption", tz_assumption)):
        if not value:
            raise ValueError(f"provenance field '{name}' must be non-empty")
    return {
        "parser_version": f"{parser}@{version}",
        "tz_assumption": tz_assumption,
        "family": family,
    }
