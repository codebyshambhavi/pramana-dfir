"""Phase 3: T8 Reconstruction Engine Event & Relationship Compatibility Tests.

Verifies that T8 (`intelligence/hyp/reconstruct.py`):
- Consumes normalised events (`event_id`, `case_id`, `evidence_id`, `event_type`,
  `event_time_utc`, `raw_timestamp`, `source_locator`, `extraction_quality`) and
  Event v1.1 payloads cleanly.
- Preserves event-to-evidence and event-to-source-locator traceability across:
  * Gmail / Outlook (Message-ID)
  * PST (folder path / item / message ID)
  * PCAP (packet / frame number)
  * Zeek (UID)
  * Logs (line / row / byte offset)
- Links relationships (PRIMARY and SECONDARY) and hypotheses to reconstructed events.
- Explicitly handles missing timestamps, conflicting timestamps, chronology
  uncertainty, contradictory events, and duplicate event IDs without fabricating
  chronology or dropping provenance.
- Enforces strict case isolation and deterministic output tied to `analysis_run_id`.
"""
from __future__ import annotations

import copy
from typing import Any

import pytest

from intelligence.hyp.engine import evaluate_hypotheses
from intelligence.hyp.reconstruct import (
    extract_source_locator_details,
    normalize_event_for_reconstruction,
    reconstruct_narrative,
)


def _contract_event(
    event_id: str,
    *,
    case_id: str = "CASE-T8-COMPAT",
    evidence_id: str = "EVID-001",
    event_type: str = "file_access",
    source: str = "log",
    event_time_utc: str | None = "2026-10-18T02:00:00Z",
    raw_timestamp: str | None = "2026-10-18T07:30:00+05:30",
    source_locator: str = "system.log#line=42&offset=2048",
    extraction_quality: str = "HIGH",
    actor: str = "mira.chen",
    device: str = "wks-07",
    obj: str = "Q4-board-deck.pdf",
    ip: str = "198.51.100.42",
    tz_assumption: str = "explicit_offset",
    raw: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": event_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "event_type": event_type,
        "source": source,
        "event_time_utc": event_time_utc,
        "raw_timestamp": raw_timestamp,
        "source_locator": source_locator,
        "extraction_quality": extraction_quality,
        "actor": actor,
        "device": device,
        "object": obj,
        "ip": ip,
        "tz_assumption": tz_assumption,
        "sha256": "b" * 64,
        "raw": raw or {
            "timestamp": raw_timestamp,
            "source_locator": source_locator,
            "extraction_quality": extraction_quality,
        },
    }
    if event_time_utc is not None:
        payload["timestamp"] = event_time_utc
    return payload


def _make_primary_rel(
    rel_id: str,
    source_event_id: str,
    target_event_id: str,
    *,
    case_id: str = "CASE-T8-COMPAT",
    evidence_refs: list[str] | None = None,
    parameter_id: str = "P01_EXACT_MESSAGE_ID",
) -> dict[str, Any]:
    return {
        "relationship_id": rel_id,
        "case_id": case_id,
        "source_event_id": source_event_id,
        "target_event_id": target_event_id,
        "relationship_type": "PRIMARY",
        "score": None,
        "threshold_version": "1.0.0-provisional",
        "feature_contributions": [
            {
                "parameter_id": parameter_id,
                "kind": "anchor",
                "value": 1.0,
                "weight": 1.0,
                "contribution": 1.0,
                "status": "ANCHORED",
            }
        ],
        "counter_signals": [],
        "explanation": f"PRIMARY relationship {rel_id} via {parameter_id}.",
        "evidence_refs": evidence_refs or ["EVID-001", "EVID-002"],
        "review_status": "VALIDATED_DIRECT",
        "config_version": "corr-config-v1",
    }


def _make_secondary_rel(
    rel_id: str,
    source_event_id: str,
    target_event_id: str,
    *,
    case_id: str = "CASE-T8-COMPAT",
    score: float = 0.78,
    evidence_refs: list[str] | None = None,
    counter_signals: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "relationship_id": rel_id,
        "case_id": case_id,
        "source_event_id": source_event_id,
        "target_event_id": target_event_id,
        "relationship_type": "SECONDARY",
        "score": score,
        "threshold_version": "1.0.0-provisional",
        "feature_contributions": [
            {
                "parameter_id": "P19_TEMPORAL_PROXIMITY",
                "kind": "feature",
                "value": score,
                "weight": 0.12,
                "contribution": round(score * 0.12, 4),
            }
        ],
        "counter_signals": counter_signals or [],
        "explanation": f"SECONDARY relationship {rel_id} with score={score:.2f}.",
        "evidence_refs": evidence_refs or ["EVID-001", "EVID-002"],
        "review_status": "HIGH_CONFIDENCE",
        "config_version": "corr-config-v1",
    }


def test_normalised_event_ingestion_and_evidence_traceability():
    """T8 ingests Section 5.6 normalised events and preserves all contract fields."""
    ev1 = _contract_event(
        "EV-NORM-1",
        evidence_id="EVID-LOG-01",
        event_type="archive_create",
        source="log",
        event_time_utc="2026-10-18T02:00:00Z",
        raw_timestamp="2026-10-18T07:30:00+05:30",
        source_locator="audit.log#line=108&offset=4096",
        extraction_quality="HIGH",
    )
    ev2 = _contract_event(
        "EV-NORM-2",
        evidence_id="EVID-GMAIL-01",
        event_type="file_upload",
        source="gmail",
        event_time_utc="2026-10-18T02:04:00Z",
        raw_timestamp="Sun, 18 Oct 2026 07:34:00 +0530",
        source_locator="gmail:message_id=<msg-901@corp.example>",
        extraction_quality="VERIFIED",
    )
    rel = _make_primary_rel(
        "rel_" + "1" * 64,
        "EV-NORM-1",
        "EV-NORM-2",
        evidence_refs=["EVID-LOG-01", "EVID-GMAIL-01"],
    )

    hyp_res = evaluate_hypotheses(
        claims=[],
        events=[ev1, ev2],
        relationships=[rel],
        case_id="CASE-T8-COMPAT",
        analysis_run_id="RUN-T8-NORM-01",
    )
    top_hyp = hyp_res.ranked_hypotheses[0]

    recon = reconstruct_narrative(
        hypothesis=top_hyp,
        claims=[],
        events=[ev1, ev2],
        h0_event_ids=hyp_res.h0_residual.unassigned_event_ids,
        relationships=[rel],
        case_id="CASE-T8-COMPAT",
        analysis_run_id="RUN-T8-NORM-01",
    )
    data = recon.to_dict()

    assert data["case_id"] == "CASE-T8-COMPAT"
    assert data["analysis_run_id"] == "RUN-T8-NORM-01"
    assert set(data["evidence_ids"]) == {"EVID-LOG-01", "EVID-GMAIL-01"}
    assert len(data["events"]) == 2

    by_id = {e["event_id"]: e for e in data["events"]}
    assert by_id["EV-NORM-1"]["evidence_id"] == "EVID-LOG-01"
    assert by_id["EV-NORM-1"]["event_type"] == "archive_create"
    assert by_id["EV-NORM-1"]["event_time_utc"] == "2026-10-18T02:00:00Z"
    assert by_id["EV-NORM-1"]["raw_timestamp"] == "2026-10-18T07:30:00+05:30"
    assert by_id["EV-NORM-1"]["source_locator"] == "audit.log#line=108&offset=4096"
    assert by_id["EV-NORM-1"]["extraction_quality"] == "HIGH"
    assert by_id["EV-NORM-1"]["analysis_run_id"] == "RUN-T8-NORM-01"

    assert by_id["EV-NORM-2"]["evidence_id"] == "EVID-GMAIL-01"
    assert by_id["EV-NORM-2"]["event_type"] == "file_upload"
    assert by_id["EV-NORM-2"]["source_locator"] == "gmail:message_id=<msg-901@corp.example>"
    assert by_id["EV-NORM-2"]["extraction_quality"] == "VERIFIED"


def test_source_locator_traceability_across_all_required_forensic_sources():
    """T8 preserves structured source locators across Gmail/Outlook, PST, PCAP, Zeek, and logs."""
    events = [
        _contract_event(
            "EV-GMAIL",
            evidence_id="EVID-GMAIL",
            source="gmail",
            event_type="email_sent",
            event_time_utc="2026-10-18T02:00:00Z",
            source_locator="gmail:message_id=<exfil-01@gmail.example>",
            raw={"message_id": "<exfil-01@gmail.example>"},
        ),
        _contract_event(
            "EV-OUTLOOK",
            evidence_id="EVID-OUTLOOK",
            source="outlook",
            event_type="email_received",
            event_time_utc="2026-10-18T02:01:00Z",
            source_locator="outlook:message_id=<exfil-01@gmail.example>",
            raw={"Message-ID": "<exfil-01@gmail.example>"},
        ),
        _contract_event(
            "EV-PST",
            evidence_id="EVID-PST",
            source="pst",
            event_type="archive_create",
            event_time_utc="2026-10-18T02:02:00Z",
            source_locator="pst:/Top of Personal Folders/Sent Items#item_id=2097188&message_id=<pst-77@corp.local>",
            raw={
                "folder_path": "/Top of Personal Folders/Sent Items",
                "item_id": "2097188",
                "message_id": "<pst-77@corp.local>",
            },
        ),
        _contract_event(
            "EV-PCAP",
            evidence_id="EVID-PCAP",
            source="pcap",
            event_type="network_flow",
            event_time_utc="2026-10-18T02:03:00Z",
            source_locator="capture.pcap#packet=412",
            raw={"packet_number": 412, "frame_number": 412},
        ),
        _contract_event(
            "EV-ZEEK",
            evidence_id="EVID-ZEEK",
            source="zeek",
            event_type="file_upload",
            event_time_utc="2026-10-18T02:04:00Z",
            source_locator="conn.log#uid=C9x8v7W6u5T4s3R2q1&line=88",
            raw={"uid": "C9x8v7W6u5T4s3R2q1"},
        ),
        _contract_event(
            "EV-LOG",
            evidence_id="EVID-LOG",
            source="log",
            event_type="file_access",
            event_time_utc="2026-10-18T02:05:00Z",
            source_locator="syslog.csv#line=314&offset=16384",
            raw={"line_number": 314, "byte_offset": 16384},
        ),
    ]

    rels = [
        _make_primary_rel("rel_" + "a" * 64, "EV-GMAIL", "EV-OUTLOOK", evidence_refs=["EVID-GMAIL", "EVID-OUTLOOK"]),
        _make_primary_rel("rel_" + "b" * 64, "EV-PST", "EV-ZEEK", evidence_refs=["EVID-PST", "EVID-ZEEK"], parameter_id="P05_EXACT_ATTACHMENT_SHA256"),
        _make_primary_rel("rel_" + "c" * 64, "EV-PCAP", "EV-LOG", evidence_refs=["EVID-PCAP", "EVID-LOG"], parameter_id="P10_EXACT_ZEEK_UID"),
    ]

    hyp_res = evaluate_hypotheses(
        claims=[],
        events=events,
        relationships=rels,
        case_id="CASE-T8-COMPAT",
        analysis_run_id="RUN-LOCATORS-01",
    )
    recon = reconstruct_narrative(
        hypothesis=hyp_res.ranked_hypotheses[0],
        claims=[],
        events=events,
        h0_event_ids=hyp_res.h0_residual.unassigned_event_ids,
        relationships=rels,
        case_id="CASE-T8-COMPAT",
        analysis_run_id="RUN-LOCATORS-01",
    )

    by_id = {e["event_id"]: e for e in recon.events}

    # 1. Gmail & Outlook Message-ID
    assert by_id["EV-GMAIL"]["source_locator_details"]["message_id"] == "<exfil-01@gmail.example>"
    assert by_id["EV-OUTLOOK"]["source_locator_details"]["message_id"] == "<exfil-01@gmail.example>"

    # 2. PST folder path / item ID / message ID
    pst_loc = by_id["EV-PST"]["source_locator_details"]
    assert pst_loc["pst_folder_path"] == "/Top of Personal Folders/Sent Items"
    assert pst_loc["pst_item_id"] == "2097188"
    assert pst_loc["message_id"] == "<pst-77@corp.local>"

    # 3. PCAP packet / frame number
    pcap_loc = by_id["EV-PCAP"]["source_locator_details"]
    assert pcap_loc["packet_number"] == 412

    # 4. Zeek UID
    zeek_loc = by_id["EV-ZEEK"]["source_locator_details"]
    assert zeek_loc["zeek_uid"] == "C9x8v7W6u5T4s3R2q1"
    assert zeek_loc["line_number"] == 88

    # 5. Log line & byte offset
    log_loc = by_id["EV-LOG"]["source_locator_details"]
    assert log_loc["line_number"] == 314
    assert log_loc["byte_offset"] == 16384


def test_relationship_linked_reconstruction_preserves_primary_and_secondary_links():
    """T8 attaches relationship references and summaries to both timeline events and stages."""
    ev1 = _contract_event("EV-1", evidence_id="EVID-1", event_type="archive_create", event_time_utc="2026-10-18T02:00:00Z")
    ev2 = _contract_event("EV-2", evidence_id="EVID-2", event_type="file_upload", source="browser", event_time_utc="2026-10-18T02:05:00Z")
    ev3 = _contract_event("EV-3", evidence_id="EVID-3", event_type="message_sent", source="chat", event_time_utc="2026-10-18T02:06:00Z")

    rel_primary = _make_primary_rel("rel_" + "p" * 64, "EV-1", "EV-2", evidence_refs=["EVID-1", "EVID-2"])
    rel_secondary = _make_secondary_rel("rel_" + "s" * 64, "EV-2", "EV-3", score=0.81, evidence_refs=["EVID-2", "EVID-3"])

    hyp_res = evaluate_hypotheses(
        claims=[],
        events=[ev1, ev2, ev3],
        relationships=[rel_primary, rel_secondary],
        case_id="CASE-T8-COMPAT",
        analysis_run_id="RUN-REL-LINK",
    )
    recon = reconstruct_narrative(
        hypothesis=hyp_res.ranked_hypotheses[0],
        claims=[],
        events=[ev1, ev2, ev3],
        h0_event_ids=hyp_res.h0_residual.unassigned_event_ids,
        relationships=[rel_primary, rel_secondary],
        case_id="CASE-T8-COMPAT",
        analysis_run_id="RUN-REL-LINK",
    )

    assert set(recon.relationship_ids) == {rel_primary["relationship_id"], rel_secondary["relationship_id"]}
    by_id = {e["event_id"]: e for e in recon.events}
    assert rel_primary["relationship_id"] in by_id["EV-1"]["relationship_ids"]
    assert set(by_id["EV-2"]["relationship_ids"]) == {
        rel_primary["relationship_id"],
        rel_secondary["relationship_id"],
    }
    rel_types_on_ev2 = {r["relationship_type"] for r in by_id["EV-2"]["relationships"]}
    assert rel_types_on_ev2 == {"PRIMARY", "SECONDARY"}
    top_id = hyp_res.ranked_hypotheses[0].id
    assert top_id in by_id["EV-1"]["hypothesis_ids"]
    assert top_id in by_id["EV-2"]["hypothesis_ids"]


def test_missing_and_conflicting_timestamps_handled_explicitly():
    """T8 records missing timestamps and conflicting raw vs UTC timestamps without inventing times."""
    ev_valid = _contract_event(
        "EV-VALID",
        evidence_id="EVID-1",
        event_type="archive_create",
        event_time_utc="2026-10-18T02:00:00Z",
        raw_timestamp="2026-10-18T02:00:00Z",
    )
    # Event with missing timestamp
    ev_missing_ts = {
        "event_id": "EV-MISSING-TS",
        "case_id": "CASE-T8-COMPAT",
        "evidence_id": "EVID-2",
        "event_type": "file_access",
        "source": "pst",
        "event_time_utc": None,
        "raw_timestamp": None,
        "source_locator": "pst:/Drafts#item_id=99",
        "extraction_quality": "PARTIAL",
    }
    # Event where raw_timestamp conflicts with event_time_utc by 3 hours
    ev_conflict_ts = _contract_event(
        "EV-CONFLICT-TS",
        evidence_id="EVID-3",
        event_type="file_upload",
        source="browser",
        event_time_utc="2026-10-18T02:05:00Z",
        raw_timestamp="2026-10-18T05:05:00Z",
        source_locator="browser_history.csv#row=12",
    )

    rel = _make_primary_rel("rel_" + "d" * 64, "EV-VALID", "EV-CONFLICT-TS", evidence_refs=["EVID-1", "EVID-3"])
    hyp_res = evaluate_hypotheses(
        claims=[],
        events=[ev_valid, ev_conflict_ts],
        relationships=[rel],
        case_id="CASE-T8-COMPAT",
        analysis_run_id="RUN-TS-EDGE",
    )

    recon = reconstruct_narrative(
        hypothesis=hyp_res.ranked_hypotheses[0],
        claims=[],
        events=[ev_valid, ev_missing_ts, ev_conflict_ts],
        h0_event_ids=["EV-MISSING-TS"],
        relationships=[rel],
        case_id="CASE-T8-COMPAT",
        analysis_run_id="RUN-TS-EDGE",
    )
    data = recon.to_dict()

    # Missing timestamp is explicitly surfaced, never fabricated
    assert "EV-MISSING-TS" in data["missing_timestamp_event_ids"]
    missing_entry = next(m for m in data["missing_timestamp_events"] if m["event_id"] == "EV-MISSING-TS")
    assert missing_entry["evidence_id"] == "EVID-2"
    assert missing_entry["source_locator"] == "pst:/Drafts#item_id=99"
    assert missing_entry["chronology_uncertainty"]["status"] == "MISSING_TIMESTAMP"

    # Conflicting timestamp is explicitly surfaced
    conflict_ids = {c["event_id"] for c in data["conflicting_timestamp_events"]}
    assert "EV-CONFLICT-TS" in conflict_ids
    conflict_ev = next(e for e in data["events"] if e["event_id"] == "EV-CONFLICT-TS")
    assert conflict_ev["chronology_uncertainty"]["status"] == "CONFLICTING_TIMESTAMPS"
    assert conflict_ev["chronology_uncertainty"]["discrepancy_seconds"] == 10800.0


def test_chronology_uncertainty_and_contradictory_events_preserved():
    """T8 surfaces chronology uncertainty (out-of-order stages / timezone uncertainty) and contradictory events."""
    # Access stage events occur at 03:30 UTC, while Collection/Exfiltration occur earlier at 02:00-02:05 UTC -> OUT_OF_ORDER
    ev_access = {
        **_contract_event(
            "EV-ACCESS",
            evidence_id="EVID-0",
            event_type="login",
            source="log",
            event_time_utc="2026-10-18T03:30:00Z",
            raw_timestamp="2026-10-18T03:30:00",
            tz_assumption="assumed_case_tz",
        ),
        "family": "authentication",
    }
    ev_collect = _contract_event(
        "EV-COLLECT",
        evidence_id="EVID-1",
        event_type="archive_create",
        source="log",
        event_time_utc="2026-10-18T02:00:00Z",
        raw_timestamp="2026-10-18T02:00:00",
        tz_assumption="assumed_case_tz",
    )
    ev_exfil = _contract_event(
        "EV-EXFIL",
        evidence_id="EVID-2",
        event_type="file_upload",
        source="browser",
        event_time_utc="2026-10-18T02:05:00Z",
        raw_timestamp="2026-10-18T02:05:00Z",
        tz_assumption="explicit_utc",
    )
    access_claim = {
        "claim_id": "CLM-ACCESS-LATE",
        "claim_key": "KEY-ACCESS-LATE",
        "case_id": "CASE-T8-COMPAT",
        "type": "ACTOR_DEVICE_CONSISTENT",
        "status": "CORROBORATED",
        "grade": "A",
        "params": {"actor": "mira.chen", "device": "wks-07"},
        "edges": [{"ref_kind": "event", "ref_id": "EV-ACCESS", "role": "SUPPORTS"}],
    }
    staging_claim = {
        "claim_id": "CLM-STAGING-EARLY",
        "claim_key": "KEY-STAGING-EARLY",
        "case_id": "CASE-T8-COMPAT",
        "type": "OFFHOURS_SESSION",
        "status": "ASSERTED",
        "grade": "B",
        "params": {"actor": "mira.chen", "device": "wks-07"},
        "edges": [{"ref_kind": "event", "ref_id": "EV-COLLECT", "role": "SUPPORTS"}],
    }
    rel_flow = {
        **_make_primary_rel("rel_" + "e" * 64, "EV-COLLECT", "EV-EXFIL"),
        "actor": None,
        "device": None,
    }
    # Clear actor/device on collect/exfil so only access_claim satisfies the access stage at 03:30 UTC
    ev_collect_no_actor = {**ev_collect, "actor": None, "device": None}
    ev_exfil_no_actor = {**ev_exfil, "actor": None, "device": None}
    rel_contra = _make_secondary_rel(
        "rel_" + "f" * 64,
        "EV-COLLECT",
        "EV-EXFIL",
        score=0.35,
        counter_signals=[
            {
                "parameter_id": "LOCATION_CONFLICT",
                "value": 1.0,
                "reason": "Upload timestamp precedes archive creation timestamp across clocks",
            }
        ],
    )

    hyp_res = evaluate_hypotheses(
        claims=[access_claim, staging_claim],
        events=[ev_access, ev_collect_no_actor, ev_exfil_no_actor],
        relationships=[rel_flow, rel_contra],
        case_id="CASE-T8-COMPAT",
        analysis_run_id="RUN-CHRONO-CONTRA",
    )
    h1 = next(h for h in hyp_res.ranked_hypotheses if h.id == "H1")
    recon = reconstruct_narrative(
        hypothesis=h1,
        claims=[access_claim, staging_claim],
        events=[ev_access, ev_collect_no_actor, ev_exfil_no_actor],
        h0_event_ids=hyp_res.h0_residual.unassigned_event_ids,
        relationships=[rel_flow, rel_contra],
        case_id="CASE-T8-COMPAT",
        analysis_run_id="RUN-CHRONO-CONTRA",
    )
    data = recon.to_dict()

    # Contradictions surfaced at both top-level and per-event level
    assert len(data["contradictions"]) >= 1
    assert any(c["type"] in ("LOCATION_CONFLICT", "COUNTER_SIGNAL") for c in data["contradictions"])
    by_id = {e["event_id"]: e for e in data["events"]}
    assert len(by_id["EV-COLLECT"]["contradictions"]) >= 1
    assert len(by_id["EV-EXFIL"]["contradictions"]) >= 1

    # Chronology uncertainties include both event-level assumed_case_tz and stage-level OUT_OF_ORDER
    uncertainty_kinds = {u.get("kind") for u in data["chronology_uncertainties"]}
    assert "EVENT_TIMESTAMP_UNCERTAINTY" in uncertainty_kinds
    assert "STAGE_OUT_OF_ORDER" in uncertainty_kinds


def test_duplicate_event_handling_and_deterministic_reconstruction():
    """T8 deduplicates repeated event IDs deterministically and produces identical output across permutations."""
    ev1 = _contract_event("EV-DUP-1", evidence_id="EVID-1", event_type="archive_create", event_time_utc="2026-10-18T02:00:00Z")
    ev2 = _contract_event("EV-DUP-2", evidence_id="EVID-2", event_type="file_upload", source="browser", event_time_utc="2026-10-18T02:05:00Z")
    ev1_dup = copy.deepcopy(ev1)

    rel = _make_primary_rel("rel_" + "9" * 64, "EV-DUP-1", "EV-DUP-2")
    hyp_res = evaluate_hypotheses(
        claims=[],
        events=[ev1, ev2],
        relationships=[rel],
        case_id="CASE-T8-COMPAT",
        analysis_run_id="RUN-DET-T8",
    )
    top_hyp = hyp_res.ranked_hypotheses[0]

    recon_a = reconstruct_narrative(
        hypothesis=top_hyp,
        claims=[],
        events=[ev1, ev2, ev1_dup],
        h0_event_ids=[],
        relationships=[rel],
        case_id="CASE-T8-COMPAT",
        analysis_run_id="RUN-DET-T8",
    )
    recon_b = reconstruct_narrative(
        hypothesis=top_hyp,
        claims=[],
        events=[ev2, ev1_dup, ev1],
        h0_event_ids=[],
        relationships=[rel],
        case_id="CASE-T8-COMPAT",
        analysis_run_id="RUN-DET-T8",
    )

    assert recon_a.duplicate_event_ids == ["EV-DUP-1"]
    assert len(recon_a.events) == 2
    assert recon_a.to_dict() == recon_b.to_dict()


def test_case_isolation_enforced_in_t8():
    """T8 rejects cross-case events or cross-case relationships."""
    ev_case_a = _contract_event("EV-A1", case_id="CASE-A")
    ev_case_b = _contract_event("EV-B1", case_id="CASE-B")
    rel_case_a = _make_primary_rel("rel_" + "7" * 64, "EV-A1", "EV-A2", case_id="CASE-A")

    hyp_res = evaluate_hypotheses(
        claims=[],
        events=[ev_case_a],
        case_id="CASE-A",
        analysis_run_id="RUN-ISO",
    )

    with pytest.raises(ValueError, match="Case isolation violation"):
        reconstruct_narrative(
            hypothesis=hyp_res.ranked_hypotheses[0],
            claims=[],
            events=[ev_case_a, ev_case_b],
            h0_event_ids=[],
            case_id="CASE-A",
        )

    with pytest.raises(ValueError, match="Case isolation violation"):
        reconstruct_narrative(
            hypothesis=hyp_res.ranked_hypotheses[0],
            claims=[],
            events=[ev_case_b],
            h0_event_ids=[],
            relationships=[rel_case_a],
            case_id="CASE-B",
        )
