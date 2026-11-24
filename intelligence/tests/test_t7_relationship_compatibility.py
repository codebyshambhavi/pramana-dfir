"""Phase 2: T7 Hypothesis Engine Relationship & Normalised Event Compatibility Tests.

Covers:
1. Primary relationship consumed by T7.
2. Secondary relationship consumed by T7 (and distinction from Primary).
3. Supporting evidence and relationship references on hypotheses.
4. Contradicting evidence and relationship references on hypotheses.
5. Multiple relationships contributing to one hypothesis.
6. Missing or unavailable evidence references (never treated as contradictory).
7. Invalid or incomplete relationship payloads rejected.
8. High secondary correlation score never auto-confirms a forensic conclusion.
9. Machine-generated hypotheses vs investigator-confirmed conclusions distinction.
10. Deterministic hypothesis generation.
11. Case isolation enforcement.
12. Analysis-run association.
"""
from __future__ import annotations

import pytest

from intelligence.correlation.registry import load_registry
from intelligence.correlation.service import correlate_case_events
from intelligence.hyp.engine import (
    STATE_SATISFIED,
    STATE_UNOBSERVABLE,
    STATE_VIOLATED,
    STATUS_LEADING,
    STATUS_REFUTED,
    STATUS_UNDETERMINED,
    adapt_relationships_for_hypotheses,
    evaluate_hypotheses,
    validate_relationship_payload,
)


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_SHARED_ATTACHMENT = "c" * 64


def _make_norm_event(
    event_id: str,
    *,
    case_id: str = "CASE-T7-REL",
    evidence_id: str = "EVID-001",
    source: str = "system_log",
    action: str = "login",
    timestamp: str = "2026-10-18T02:00:00Z",
    actor: str = "alice@corp.example",
    device: str = "laptop-01",
    obj: str | None = "secrets.tar.gz",
    ip: str = "10.10.1.15",
    locator: str = "system_log.csv#row=1",
    raw: dict | None = None,
) -> dict:
    return {
        "event_id": event_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "artifact_ref": locator,
        "source_locator": locator,
        "sha256": SHA_A,
        "timestamp": timestamp,
        "event_time_utc": timestamp,
        "raw_timestamp": timestamp,
        "source": source,
        "action": action,
        "event_type": action,
        "actor": actor,
        "device": device,
        "object": obj,
        "ip": ip,
        "raw": raw or {"content_hash": SHA_SHARED_ATTACHMENT},
        "parser_version": f"{source}@1.1.0",
        "tz_assumption": "explicit_offset",
        "extraction_quality": {
            "parser_confidence": 0.99,
            "tz_assumption": "explicit_offset",
            "warnings": [],
        },
    }


def _primary_relationship(
    rel_id: str = "rel_" + "1" * 64,
    *,
    case_id: str = "CASE-T7-REL",
    source_event_id: str = "EV-1",
    target_event_id: str = "EV-2",
    evidence_refs: list[str] | None = None,
    config_version: str = "corr-config-v1",
) -> dict:
    refs = ["EVID-001", "EVID-002"] if evidence_refs is None else evidence_refs
    return {
        "relationship_id": rel_id,
        "case_id": case_id,
        "source_event_id": source_event_id,
        "target_event_id": target_event_id,
        "relationship_type": "PRIMARY",
        "status": "VALIDATED_DIRECT",
        "review_status": "VALIDATED_DIRECT",
        "confidence": "DIRECT",
        "score": None,
        "threshold_version": config_version,
        "config_version": config_version,
        "registry_version": "corr-registry-v1",
        "registry_hash": "2" * 64,
        "anchor_type": ["ANCHOR_EXACT"],
        "anchors": [
            {
                "parameter_id": "ANCHOR_FILE_SHA256",
                "status": "ANCHORED",
                "anchor_type": "ANCHOR_EXACT",
                "value_reference": SHA_SHARED_ATTACHMENT[:16],
                "source_event_ids": [source_event_id, target_event_id],
                "evidence_refs": refs,
                "explanation": "Both events reference identical validated SHA-256 content.",
            }
        ],
        "feature_contributions": [],
        "counter_signals": [],
        "evidence_refs": refs,
        "evidence_pointers": {
            "source": {"evidence_id": refs[0] if refs else None, "artifact_ref": "sys.csv#row=1", "source": "log"},
            "target": {"evidence_id": refs[-1] if refs else None, "artifact_ref": "browser.csv#row=2", "source": "browser"},
        },
        "explanation": "Primary relationship established by ANCHOR_EXACT. Both events reference identical validated SHA-256 content.",
    }


def _secondary_relationship(
    rel_id: str = "rel_" + "3" * 64,
    *,
    case_id: str = "CASE-T7-REL",
    source_event_id: str = "EV-1",
    target_event_id: str = "EV-2",
    score: float = 0.82,
    counter_signals: list[dict] | None = None,
    unavailable_parameters: list[str] | None = None,
    evidence_refs: list[str] | None = None,
    review_status: str = "REQUIRES_REVIEW",
    config_version: str = "corr-config-v1",
) -> dict:
    refs = ["EVID-001", "EVID-002"] if evidence_refs is None else evidence_refs
    return {
        "relationship_id": rel_id,
        "case_id": case_id,
        "source_event_id": source_event_id,
        "target_event_id": target_event_id,
        "relationship_type": "SECONDARY",
        "score": score,
        "threshold_version": config_version,
        "config_version": config_version,
        "feature_contributions": [
            {
                "parameter_id": "IDENTITY_EXACT_EMAIL",
                "kind": "feature",
                "value": 1.0,
                "weight": 0.30,
                "contribution": 0.30,
                "source_fields": ["actor.email"],
            },
            {
                "parameter_id": "TIME_WINDOW",
                "kind": "feature",
                "value": 0.7,
                "weight": 0.20,
                "contribution": 0.14,
                "source_fields": ["event_time_utc"],
            },
        ],
        "counter_signals": counter_signals or [],
        "unavailable_parameters": unavailable_parameters or [],
        "explanation": f"Secondary score {score:.3f}; analyst review required.",
        "evidence_refs": refs,
        "review_status": review_status,
    }


def test_primary_relationship_consumed_by_t7():
    """T7 consumes a PRIMARY relationship and maps its validated anchor into object-flow & actor support."""
    ev1 = _make_norm_event("EV-1", evidence_id="EVID-LOG", source="system_log", action="archive_create")
    ev2 = _make_norm_event("EV-2", evidence_id="EVID-WEB", source="browser", action="file_upload", timestamp="2026-10-18T02:05:00Z")
    rel = _primary_relationship(evidence_refs=["EVID-LOG", "EVID-WEB"])

    res = evaluate_hypotheses(
        claims=[],
        events=[ev1, ev2],
        relationships=[rel],
        case_id="CASE-T7-REL",
        analysis_run_id="RUN-PRIM-01",
    )

    assert res.consumed_relationships_count == 1
    assert res.primary_relationships_count == 1
    assert res.secondary_relationships_count == 0
    assert res.correlation_config_version == "corr-config-v1"

    h1 = next(h for h in res.ranked_hypotheses if h.id == "H1")
    req_flow = next(e for e in h1.evaluations if e.item_id == "H1-REQ-2")
    assert req_flow.state == STATE_SATISFIED
    assert rel["relationship_id"] in req_flow.matched_relationship_ids
    assert rel["relationship_id"] in h1.supporting_relationship_ids
    assert rel["relationship_id"] in h1.primary_relationship_ids
    assert h1.secondary_relationship_ids == []
    assert set(h1.supporting_evidence_ids) == {"EVID-LOG", "EVID-WEB"}
    assert set(h1.supporting_event_ids) == {"EV-1", "EV-2"}


def test_secondary_relationship_consumed_by_t7_preserves_primary_secondary_distinction():
    """T7 consumes a SECONDARY relationship as contextual corroboration only.
    Even with a high score (0.95), a SECONDARY relationship never satisfies direct SAME_OBJECT_FLOW
    and never auto-confirms a hypothesis as LEADING or investigator-confirmed.
    """
    ev1 = _make_norm_event("EV-1", evidence_id="EVID-LOG", source="system_log", action="login")
    ev2 = _make_norm_event("EV-2", evidence_id="EVID-WEB", source="browser", action="file_upload", timestamp="2026-10-18T02:05:00Z")
    sec_rel = _secondary_relationship(score=0.95, review_status="HIGH_CONFIDENCE", evidence_refs=["EVID-LOG", "EVID-WEB"])

    res = evaluate_hypotheses(
        claims=[],
        events=[ev1, ev2],
        relationships=[sec_rel],
        case_id="CASE-T7-REL",
        analysis_run_id="RUN-SEC-01",
    )

    assert res.consumed_relationships_count == 1
    assert res.primary_relationships_count == 0
    assert res.secondary_relationships_count == 1

    h1 = next(h for h in res.ranked_hypotheses if h.id == "H1")
    # Contextual actor/device consistency is supported by the secondary relationship
    req_actor = next(e for e in h1.evaluations if e.item_id == "H1-REQ-1")
    assert req_actor.state == STATE_SATISFIED
    assert sec_rel["relationship_id"] in h1.supporting_relationship_ids
    assert sec_rel["relationship_id"] in h1.secondary_relationship_ids
    assert h1.primary_relationship_ids == []

    # Direct SAME_OBJECT_FLOW requirement is NOT satisfied by a secondary relationship alone
    req_flow = next(e for e in h1.evaluations if e.item_id == "H1-REQ-2")
    assert req_flow.state != STATE_SATISFIED

    # High secondary score must not produce a LEADING or investigator-confirmed conclusion
    assert h1.status != STATUS_LEADING
    assert res.outcome == STATUS_UNDETERMINED
    for h in res.ranked_hypotheses:
        assert h.conclusion_type == "MACHINE_HYPOTHESIS"
        assert h.investigator_confirmed is False


def test_supporting_and_contradicting_evidence_and_relationship_references():
    """Hypotheses retain both supporting and contradicting relationship and evidence references."""
    ev1 = _make_norm_event("EV-1", evidence_id="EVID-LOG", source="system_log", action="archive_create")
    ev2 = _make_norm_event("EV-2", evidence_id="EVID-WEB", source="browser", action="file_upload", timestamp="2026-10-18T02:05:00Z")
    ev3 = _make_norm_event("EV-3", evidence_id="EVID-AUTH", source="auth", action="token_refresh", timestamp="2026-10-18T02:02:00Z", ip="198.51.100.99")

    rel_support = _primary_relationship(
        rel_id="rel_" + "a" * 64,
        source_event_id="EV-1",
        target_event_id="EV-2",
        evidence_refs=["EVID-LOG", "EVID-WEB"],
    )
    rel_contradict = _secondary_relationship(
        rel_id="rel_" + "b" * 64,
        source_event_id="EV-1",
        target_event_id="EV-3",
        score=0.42,
        evidence_refs=["EVID-LOG", "EVID-AUTH"],
        counter_signals=[
            {
                "parameter_id": "SESSION_ORIGIN_MISMATCH",
                "value": 1.0,
                "reason": "Conflicting remote IP origin during active session",
            }
        ],
    )

    res = evaluate_hypotheses(
        claims=[],
        events=[ev1, ev2, ev3],
        relationships=[rel_support, rel_contradict],
        case_id="CASE-T7-REL",
        analysis_run_id="RUN-MIX-01",
    )

    h1 = next(h for h in res.ranked_hypotheses if h.id == "H1")
    # H1 forbids SESSION_ORIGIN_MISMATCH -> violated by rel_contradict
    forbid_item = next(e for e in h1.evaluations if e.item_id == "H1-FORBID-1")
    assert forbid_item.state == STATE_VIOLATED
    assert rel_support["relationship_id"] in h1.supporting_relationship_ids
    assert rel_contradict["relationship_id"] in h1.contradicting_relationship_ids
    assert set(h1.supporting_evidence_ids) == {"EVID-LOG", "EVID-WEB"}
    assert "EVID-AUTH" in h1.contradicting_evidence_ids
    assert "EV-3" in h1.contradicting_event_ids
    assert h1.status == STATUS_REFUTED

    # Meanwhile H3 (Session Misuse) requires SESSION_ORIGIN_MISMATCH -> supported by rel_contradict
    h3 = next(h for h in res.ranked_hypotheses if h.id == "H3")
    h3_req = next(e for e in h3.evaluations if e.item_id == "H3-REQ-1")
    assert h3_req.state == STATE_SATISFIED
    assert rel_contradict["relationship_id"] in h3.supporting_relationship_ids


def test_multiple_relationships_contributing_to_one_hypothesis():
    """Multiple PRIMARY and SECONDARY relationships can contribute to the same hypothesis."""
    ev1 = _make_norm_event("EV-1", evidence_id="EVID-1", source="system_log", action="login", timestamp="2026-10-18T14:00:00Z")
    ev2 = _make_norm_event("EV-2", evidence_id="EVID-2", source="browser", action="file_upload", timestamp="2026-10-18T14:10:00Z")
    ev3 = _make_norm_event("EV-3", evidence_id="EVID-3", source="chat", action="message", timestamp="2026-10-18T14:15:00Z")

    rel_primary = _primary_relationship(
        rel_id="rel_" + "1" * 64,
        source_event_id="EV-1",
        target_event_id="EV-2",
        evidence_refs=["EVID-1", "EVID-2"],
    )
    rel_secondary = _secondary_relationship(
        rel_id="rel_" + "2" * 64,
        source_event_id="EV-2",
        target_event_id="EV-3",
        score=0.78,
        evidence_refs=["EVID-2", "EVID-3"],
    )

    res = evaluate_hypotheses(
        claims=[],
        events=[ev1, ev2, ev3],
        relationships=[rel_primary, rel_secondary],
        case_id="CASE-T7-REL",
        analysis_run_id="RUN-MULTI-01",
    )

    h2 = next(h for h in res.ranked_hypotheses if h.id == "H2")
    assert rel_primary["relationship_id"] in h2.supporting_relationship_ids
    assert rel_secondary["relationship_id"] in h2.supporting_relationship_ids
    assert rel_primary["relationship_id"] in h2.primary_relationship_ids
    assert rel_secondary["relationship_id"] in h2.secondary_relationship_ids
    assert set(h2.supporting_evidence_ids) == {"EVID-1", "EVID-2", "EVID-3"}
    assert set(h2.supporting_event_ids) == {"EV-1", "EV-2", "EV-3"}


def test_missing_evidence_references_never_treated_as_contradictory():
    """Missing evidence_refs, uncollected events, or unavailable_parameters must never be treated as contradictions."""
    ev1 = _make_norm_event("EV-1", evidence_id="EVID-1", source="system_log", action="login")
    ev2 = _make_norm_event("EV-2", evidence_id="EVID-2", source="browser", action="file_upload", timestamp="2026-10-18T02:05:00Z")

    # Relationship with empty evidence_refs and unavailable_parameters, plus a relationship pointing to an uncollected event EV-MISSING
    rel_missing_refs = _secondary_relationship(
        rel_id="rel_" + "4" * 64,
        source_event_id="EV-1",
        target_event_id="EV-2",
        score=0.65,
        evidence_refs=[],
        unavailable_parameters=["NET_SHARED_SESSION", "TIME_CLOCK_SKEW", "DEVICE_EXACT_MATCH"],
    )
    rel_uncollected_event = _secondary_relationship(
        rel_id="rel_" + "5" * 64,
        source_event_id="EV-1",
        target_event_id="EV-UNCOLLECTED-999",
        score=0.55,
        evidence_refs=[],
        unavailable_parameters=["FILE_EXACT_HASH"],
    )

    norm_rels, derived_claims = adapt_relationships_for_hypotheses(
        [rel_missing_refs, rel_uncollected_event],
        [ev1, ev2],
        case_id="CASE-T7-REL",
    )
    assert norm_rels[1]["missing_evidence_refs"] is True
    assert not any(c.get("is_contradiction_signal") for c in derived_claims)

    res = evaluate_hypotheses(
        claims=[],
        events=[ev1, ev2],
        relationships=[rel_missing_refs, rel_uncollected_event],
        case_id="CASE-T7-REL",
    )

    for h in res.ranked_hypotheses:
        assert h.contradicting_relationship_ids == []
        assert h.contradicting_claim_ids == []
        assert h.contradicting_evidence_ids == []
        # Audit log was not collected -> UNOBSERVABLE with 0.0 penalty
        for item in h.evaluations:
            if item.state == STATE_UNOBSERVABLE:
                assert item.disconfirmation_penalty == 0.0


@pytest.mark.parametrize(
    "bad_payload,expected_msg",
    [
        ("not-a-dict", "must be a mapping"),
        ({}, "missing or empty 'relationship_id'"),
        ({"relationship_id": "rel_1", "case_id": "", "source_event_id": "A", "target_event_id": "B", "relationship_type": "PRIMARY"}, "missing or empty 'case_id'"),
        ({"relationship_id": "rel_1", "case_id": "C1", "source_event_id": "A", "target_event_id": "A", "relationship_type": "PRIMARY"}, "must be distinct"),
        ({"relationship_id": "rel_1", "case_id": "C1", "source_event_id": "A", "target_event_id": "B", "relationship_type": "TERTIARY"}, "expected PRIMARY or SECONDARY"),
        ({"relationship_id": "rel_1", "case_id": "C1", "source_event_id": "A", "target_event_id": "B", "relationship_type": "SECONDARY", "score": None}, "requires a numeric score"),
        ({"relationship_id": "rel_1", "case_id": "C1", "source_event_id": "A", "target_event_id": "B", "relationship_type": "SECONDARY", "score": 1.5}, "must be in \\[0.0, 1.0\\]"),
        ({"relationship_id": "rel_1", "case_id": "C1", "source_event_id": "A", "target_event_id": "B", "relationship_type": "PRIMARY", "feature_contributions": "bad"}, "feature_contributions must be a list"),
        ({"relationship_id": "rel_1", "case_id": "C1", "source_event_id": "A", "target_event_id": "B", "relationship_type": "PRIMARY", "counter_signals": "bad"}, "counter_signals must be a list"),
        ({"relationship_id": "rel_1", "case_id": "C1", "source_event_id": "A", "target_event_id": "B", "relationship_type": "PRIMARY", "explanation": ""}, "explanation must be a non-empty string"),
    ],
)
def test_invalid_or_incomplete_relationship_payloads_rejected(bad_payload, expected_msg):
    """Malformed or incomplete relationship payloads fail closed with a clear ValueError."""
    with pytest.raises(ValueError, match=expected_msg):
        validate_relationship_payload(bad_payload)


def test_deterministic_hypothesis_generation_with_relationships():
    """Repeated evaluation and permuted relationship/event ordering produce identical rankings and hashes."""
    ev1 = _make_norm_event("EV-1", evidence_id="EVID-1", source="system_log", action="archive_create")
    ev2 = _make_norm_event("EV-2", evidence_id="EVID-2", source="browser", action="file_upload", timestamp="2026-10-18T02:05:00Z")
    ev3 = _make_norm_event("EV-3", evidence_id="EVID-3", source="chat", action="message", timestamp="2026-10-18T02:10:00Z")

    rel1 = _primary_relationship(rel_id="rel_" + "1" * 64, source_event_id="EV-1", target_event_id="EV-2", evidence_refs=["EVID-1", "EVID-2"])
    rel2 = _secondary_relationship(rel_id="rel_" + "2" * 64, source_event_id="EV-2", target_event_id="EV-3", score=0.74, evidence_refs=["EVID-2", "EVID-3"])

    res_a = evaluate_hypotheses(claims=[], events=[ev1, ev2, ev3], relationships=[rel1, rel2], case_id="CASE-T7-REL", analysis_run_id="RUN-DET")
    res_b = evaluate_hypotheses(claims=[], events=[ev3, ev1, ev2], relationships=[rel2, rel1], case_id="CASE-T7-REL", analysis_run_id="RUN-DET")

    assert res_a.ranking_hash == res_b.ranking_hash
    assert res_a.to_dict() == res_b.to_dict()


def test_case_isolation_enforced_in_t7():
    """T7 rejects relationships or events belonging to a different case."""
    ev_a = _make_norm_event("EV-1", case_id="CASE-ALPHA", evidence_id="EVID-A")
    ev_b = _make_norm_event("EV-2", case_id="CASE-ALPHA", evidence_id="EVID-B", source="browser")
    rel_wrong_case = _primary_relationship(case_id="CASE-BETA", source_event_id="EV-1", target_event_id="EV-2")

    with pytest.raises(ValueError, match="Case isolation violation"):
        evaluate_hypotheses(claims=[], events=[ev_a, ev_b], relationships=[rel_wrong_case], case_id="CASE-ALPHA")

    ev_cross = _make_norm_event("EV-3", case_id="CASE-BETA", evidence_id="EVID-C")
    with pytest.raises(ValueError, match="Case isolation violation"):
        evaluate_hypotheses(claims=[], events=[ev_a, ev_cross])


def test_analysis_run_and_shambhavi_correlation_engine_direct_integration():
    """T7 directly consumes output from Shambhavi's correlate_case_events service and preserves analysis_run_id."""
    ev_mail = _make_norm_event(
        "EV-GMAIL-1",
        case_id="CASE-LIVE-CORR",
        evidence_id="EVID-GMAIL-1",
        source="gmail",
        action="EMAIL_SENT",
        timestamp="2026-10-18T02:00:00Z",
        actor="alice@corp.example",
        obj="exfil.zip",
        locator="gmail.json#gmail-message=msg-01",
        raw={
            "id": "msg-01",
            "sender": "alice@corp.example",
            "subject": "Quarterly export",
            "attachments": [{"filename": "exfil.zip", "sha256": SHA_SHARED_ATTACHMENT, "size": 4096}],
        },
    )
    ev_web = _make_norm_event(
        "EV-WEB-1",
        case_id="CASE-LIVE-CORR",
        evidence_id="EVID-WEB-1",
        source="browser",
        action="file_upload",
        timestamp="2026-10-18T02:04:00Z",
        actor="alice@corp.example",
        obj="exfil.zip",
        locator="browser.csv#row=10",
        raw={"content_hash": SHA_SHARED_ATTACHMENT, "filename": "exfil.zip"},
    )

    registry = load_registry()
    corr_result = correlate_case_events(
        "CASE-LIVE-CORR",
        [ev_mail, ev_web],
        registry,
        evidence_context={
            "EVID-GMAIL-1": {"status": "ACTIVE", "verify_state": "MATCH"},
            "EVID-WEB-1": {"status": "ACTIVE", "verify_state": "MATCH"},
        },
    )
    assert corr_result.relationship_count >= 1

    res = evaluate_hypotheses(
        claims=[],
        events=[ev_mail, ev_web],
        relationships=corr_result.relationships,
        case_id="CASE-LIVE-CORR",
        analysis_run_id="RUN-CORR-99",
    )

    assert res.case_id == "CASE-LIVE-CORR"
    assert res.analysis_run_id == "RUN-CORR-99"
    assert res.correlation_config_version == registry.config_version
    for h in res.ranked_hypotheses:
        assert h.analysis_run_id == "RUN-CORR-99"
        assert h.case_id == "CASE-LIVE-CORR"
        assert h.correlation_config_version == registry.config_version
