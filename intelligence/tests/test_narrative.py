from __future__ import annotations

import pytest

from intelligence.narrative import write_narrative
from intelligence.tests.fixtures import (
    archive_event,
    login_event,
    upload_event,
)


def test_empty_events_return_empty_narrative() -> None:
    assert write_narrative([]) == ""


def test_narrative_cites_supplied_event_ids() -> None:
    events = [
        login_event(),
        archive_event(),
        upload_event(),
    ]

    narrative = write_narrative(events)

    for event in events:
        assert event["event_id"] in narrative


def test_narrative_is_deterministic() -> None:
    events = [
        upload_event(),
        login_event(),
        archive_event(),
    ]

    assert write_narrative(events) == write_narrative(events)


def test_narrative_is_chronological() -> None:
    events = [
        upload_event(),
        login_event(),
        archive_event(),
    ]

    narrative = write_narrative(events)

    assert narrative.index("EV-LOGIN") < narrative.index("EV-ARCHIVE")
    assert narrative.index("EV-ARCHIVE") < narrative.index("EV-UPLOAD")


def test_every_sentence_has_event_citation() -> None:
    events = [
        login_event(),
        archive_event(),
    ]

    narrative = write_narrative(events)

    for sentence in narrative.split("."):
        if sentence.strip():
            assert "EV-" in sentence


def test_no_unknown_event_ids_are_generated() -> None:
    events = [login_event()]

    narrative = write_narrative(events)

    assert "EV-LOGIN" in narrative
    assert "EV-ARCHIVE" not in narrative
    assert "EV-UPLOAD" not in narrative


def test_narrative_does_not_mutate_events() -> None:
    events = [
        login_event(),
        archive_event(),
    ]

    snapshot = [dict(event) for event in events]

    write_narrative(events)

    assert events == snapshot