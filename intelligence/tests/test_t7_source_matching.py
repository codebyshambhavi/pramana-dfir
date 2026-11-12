from __future__ import annotations

import pytest

from intelligence.hyp.engine import (
    STATE_SATISFIED,
    STATE_VIOLATED,
    HypothesisTemplate,
    TemplateItem,
    evaluate_hypotheses,
    load_templates,
)


def _event(event_id: str, source: str, *, family: str | None = None) -> dict[str, str]:
    event = {
        "event_id": event_id,
        "case_id": "CASE-SOURCE-MATCH",
        "evidence_id": "EVID-001",
        "artifact_ref": f"{source}.log#1",
        "sha256": "0" * 64,
        "timestamp": "2026-10-18T10:00:00Z",
        "source": source,
        "action": "activity",
        "actor": "alice",
        "device": "laptop-01",
    }
    if family is not None:
        event["family"] = family
    return event


def _claim(claim_id: str, claim_type: str, event_id: str) -> dict:
    return {
        "claim_id": claim_id,
        "type": claim_type,
        "status": "ASSERTED",
        "params": {},
        "edges": [{"ref_kind": "event", "ref_id": event_id, "role": "SUPPORTS"}],
    }


def _item(result, hypothesis_id: str, item_id: str):
    hypothesis = next(h for h in result.ranked_hypotheses if h.id == hypothesis_id)
    return next(item for item in hypothesis.evaluations if item.item_id == item_id)


def test_log_backed_claim_does_not_match_chat_when_unrelated_chat_exists() -> None:
    events = [_event("EV-LOG", "log"), _event("EV-CHAT", "chat")]
    templates = load_templates()

    result = evaluate_hypotheses(
        claims=[_claim("C1", "ACTOR_DEVICE_CONSISTENT", "EV-LOG")],
        events=events,
        templates=templates,
    )

    chat_expectation = _item(result, "H2", "H2-EXP-1")
    assert chat_expectation.state != STATE_SATISFIED
    assert chat_expectation.matched_claim_ids == []


def test_log_backed_claim_does_not_satisfy_chat_requirement_with_unrelated_chat() -> None:
    template = HypothesisTemplate(
        id="H-CHAT-REQUIRES",
        kind="test",
        name="Chat requirement",
        description="A chat-backed claim is required.",
        stages=["verification"],
        requires=[
            TemplateItem(
                id="REQ-CHAT",
                stage="verification",
                description="Chat-backed activity",
                claim_type="ACTOR_DEVICE_CONSISTENT",
                source_kind="chat",
                critical=True,
            )
        ],
        expects=[],
        forbids=[],
        constraints=[],
    )
    result = evaluate_hypotheses(
        claims=[_claim("C1", "ACTOR_DEVICE_CONSISTENT", "EV-LOG")],
        events=[_event("EV-LOG", "log"), _event("EV-CHAT", "chat")],
        templates=[template],
    )

    chat_requirement = _item(result, "H-CHAT-REQUIRES", "REQ-CHAT")
    assert chat_requirement.state != STATE_SATISFIED
    assert chat_requirement.matched_claim_ids == []


@pytest.mark.parametrize(
    ("source", "family"),
    [("chat", None), ("slack", None), ("log", "chat")],
)
def test_chat_source_or_family_provenance_satisfies_chat_item(
    source: str,
    family: str | None,
) -> None:
    events = [_event("EV-CHAT", source, family=family)]
    result = evaluate_hypotheses(
        claims=[_claim("C1", "ACTOR_DEVICE_CONSISTENT", "EV-CHAT")],
        events=events,
        templates=load_templates(),
    )

    chat_expectation = _item(result, "H2", "H2-EXP-1")
    assert chat_expectation.state == STATE_SATISFIED
    assert chat_expectation.matched_claim_ids == ["C1"]


def test_forbidden_claim_detection_remains_source_independent() -> None:
    events = [_event("EV-LOG", "log")]
    result = evaluate_hypotheses(
        claims=[_claim("C1", "SESSION_ORIGIN_MISMATCH", "EV-LOG")],
        events=events,
        templates=load_templates(),
    )

    forbidden_item = _item(result, "H1", "H1-FORBID-1")
    assert forbidden_item.state == STATE_VIOLATED
    assert forbidden_item.matched_claim_ids == ["C1"]
