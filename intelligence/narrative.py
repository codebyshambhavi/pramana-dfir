"""Role 2: evidence-grounded investigation narrative.

Narratives are deliberately evidence-first: every sentence must cite at least
one Event ID supplied to the function, and no unknown Event ID may appear.
"""

from __future__ import annotations

import re
from typing import Any

from .common import normalize_events

_EVENT_ID_PATTERN = re.compile(r"\bEV-[A-Za-z0-9_-]+\b")


def _sentence_parts(events: list[Any]) -> list[str]:
    """Build deterministic, evidence-cited timeline sentences."""
    sentences: list[str] = []

    for event in events:
        timestamp = event.timestamp.isoformat()
        sentence = (
            f"{timestamp}: Event {event.event_id} records "
            f"{event.source}:{event.action}"
        )

        if event.device:
            sentence += f" on device {event.device}"

        if event.actor:
            sentence += f" by actor {event.actor}"

        if event.object:
            sentence += f" involving object {event.object}"

        sentence += f" [{event.event_id}]."
        sentences.append(sentence)

    return sentences


def _validate_narrative(
    narrative: str,
    known_event_ids: set[str],
) -> str:
    """Reject uncited sentences and citations to unknown events."""
    text = narrative.strip()

    if not text:
        raise ValueError("Narrative cannot be empty.")

    sentences = [
        part.strip()
        for part in re.split(r"(?<=[.!?])\s+", text)
        if part.strip()
    ]

    if not sentences:
        raise ValueError("Narrative contains no sentences.")

    for sentence in sentences:
        cited_ids = set(_EVENT_ID_PATTERN.findall(sentence))

        if not cited_ids:
            raise ValueError(
                f"Narrative sentence has no Event citation: {sentence!r}"
            )

        unknown = cited_ids - known_event_ids

        if unknown:
            raise ValueError(
                f"Narrative cites unknown Event ID(s): {sorted(unknown)}"
            )

    return text


def write_narrative(events: list[dict]) -> str:
    """Create a deterministic timeline whose every sentence cites an input Event."""
    if not events:
        return ""

    normalized = normalize_events(events)

    known_event_ids = {event.event_id for event in normalized}

    sentences = _sentence_parts(normalized)

    narrative = " ".join(sentences)

    return _validate_narrative(
        narrative,
        known_event_ids,
    )