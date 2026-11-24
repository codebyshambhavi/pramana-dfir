"""Phases 4, 5 & 6: Immutable Analysis-Run Continuity, Shared Contract Boundaries,
and Focused End-to-End Integration Tests.

Covers:
1. Phase 4 — Immutable Analysis-Run Continuity:
   - All 10 required manifest fields (`run_id`, `case_id`, `input_evidence_hashes`,
     `parser_versions`, `correlation_config_version`, `module_versions`,
     `started_at`, `completed_at`, `status`, `output_manifest_hash`)
   - Explicit binding of T7 hypotheses and T8 reconstructions to `analysis_run_id`
   - Write-once immutability of completed runs and snapshot payloads
   - Deterministic reproducibility across identical inputs and configs
2. Phase 5 — Shared Contract Boundaries:
   - Anupriya -> Niharika: parsed multi-source evidence (Gmail, Outlook, PST,
     PCAP, Zeek, logs) with SHA-256 hashes and source locators into T7/T8
   - Shambhavi -> Niharika: `correlate_case_events` PRIMARY & SECONDARY
     relationships consumed by T7 and T8
   - Niharika -> Saiesha: T7, T8, and immutable analysis-run outputs consumed
     by `build_run_report_data` and `render_run_report_pdf`
3. Phase 6 — Focused End-to-End Integration Pipeline:
   Evidence -> Normalised Events -> Relationships -> T7 Hypotheses ->
   T8 Reconstruction -> Immutable Analysis Run
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.migrate import migrate
from app.db.models import AnalysisRun, Case, Evidence, EventModel, ImmutableRecordError, RunSnapshot
from app.reports.run_report import (
    build_report_content,
    content_hash,
    load_report_inputs,
    render_report_pdf,
)
from app.services.runs import (
    execute_analysis_run,
    get_run_details,
    verify_run_reproducibility,
)
from intelligence.correlation.registry import load_registry
from intelligence.correlation.service import correlate_case_events


@pytest.fixture()
def db_session() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    migrate(engine)
    factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _seed_multi_source_case(
    session: Session,
    tmp_path: Path,
    *,
    case_id: str = "CASE-E2E-ROLE4",
) -> tuple[list[Evidence], list[EventModel], list[dict[str, Any]]]:
    """Seed an end-to-end multi-source forensic case with real files, SHA-256 hashes,
    normalised events (Gmail, PST, Zeek, system log, browser), and correlation relationships.
    """
    session.add(Case(case_id=case_id, name="Role 4 End-to-End Continuity Case"))

    evidence_specs = [
        (
            f"{case_id}-EV-LOG",
            "endpoint_system_log.csv",
            b"timestamp,actor,device,action,object,ip\n2026-10-18T02:00:00Z,mira.chen,wks-07,archive_create,Q4-board-deck.tar.gz,198.51.100.42\n",
            "system_log",
            "log_csv",
            "log_csv@1.1.0",
            "endpoint_system_log.csv#line=2&offset=64",
        ),
        (
            f"{case_id}-EV-GMAIL",
            "gmail_message.json",
            b'{"id":"msg-901","internetMessageId":"<exfil-901@corp.example>","subject":"Q4-board-deck.tar.gz"}',
            "gmail",
            "gmail_json",
            "gmail_json@1.1.0",
            "gmail:message_id=<exfil-901@corp.example>",
        ),
        (
            f"{case_id}-EV-PST",
            "mailbox_export.pst",
            b"PST-SYNTHETIC-BINARY-EVIDENCE-PAYLOAD-901",
            "pst",
            "pst_parser",
            "pst_parser@1.1.0",
            "pst:/Top of Personal Folders/Sent Items#item_id=2097188&message_id=<exfil-901@corp.example>",
        ),
        (
            f"{case_id}-EV-ZEEK",
            "conn.log",
            b"ts\tuid\tid.orig_h\tid.resp_h\n1792289100.0\tC9x8v7W6u5T4s3R2q1\t198.51.100.42\t203.0.113.55\n",
            "zeek",
            "zeek_conn",
            "zeek_conn@1.1.0",
            "conn.log#uid=C9x8v7W6u5T4s3R2q1&line=2",
        ),
        (
            f"{case_id}-EV-WEB",
            "browser_history.csv",
            b"timestamp,actor,device,action,object,ip\n2026-10-18T02:05:00Z,mira.chen,wks-07,file_upload,https://drop.example/Q4-board-deck.tar.gz,198.51.100.42\n",
            "browser_history",
            "browser_csv",
            "browser_csv@1.1.0",
            "browser_history.csv#row=2",
        ),
    ]

    evidence_rows: list[Evidence] = []
    sha_by_evid: dict[str, str] = {}
    for evid_id, fname, raw_bytes, src_type, p_name, p_ver, locator in evidence_specs:
        fpath = tmp_path / f"{evid_id}_{fname}"
        fpath.write_bytes(raw_bytes)
        digest = hashlib.sha256(raw_bytes).hexdigest()
        sha_by_evid[evid_id] = digest
        ev_row = Evidence(
            evidence_id=evid_id,
            case_id=case_id,
            filename=fname,
            sha256=digest,
            size_bytes=len(raw_bytes),
            stored_path=str(fpath),
            source_type=src_type,
            source_identifier=evid_id,
            acquisition_method="forensic_collection",
            acquired_by="Niharika Integration Test",
            parser_name=p_name,
            parser_version=p_ver,
            parse_status="PARSED",
            parser_warnings=[],
            source_locator=locator,
        )
        session.add(ev_row)
        evidence_rows.append(ev_row)
    session.flush()

    attach_sha = "d" * 64
    events_data = [
        {
            "event_id": f"{case_id}:EV-01",
            "case_id": case_id,
            "evidence_id": f"{case_id}-EV-LOG",
            "artifact_ref": "endpoint_system_log.csv#line=2&offset=64",
            "sha256": sha_by_evid[f"{case_id}-EV-LOG"],
            "timestamp": datetime(2026, 10, 18, 2, 0, 0),
            "source": "log",
            "device": "wks-07",
            "actor": "mira.chen",
            "action": "archive_create",
            "object": "Q4-board-deck.tar.gz",
            "ip": "198.51.100.42",
            "parser_version": "log_csv@1.1.0",
            "tz_assumption": "explicit_offset",
            "family": "system_log",
            "raw": {
                "timestamp": "2026-10-18T07:30:00+05:30",
                "source_locator": "endpoint_system_log.csv#line=2&offset=64",
                "line_number": 2,
                "byte_offset": 64,
                "content_hash": attach_sha,
                "sha256": attach_sha,
                "parser_confidence": 0.95,
            },
        },
        {
            "event_id": f"{case_id}:EV-02",
            "case_id": case_id,
            "evidence_id": f"{case_id}-EV-GMAIL",
            "artifact_ref": "gmail:message_id=<exfil-901@corp.example>",
            "sha256": sha_by_evid[f"{case_id}-EV-GMAIL"],
            "timestamp": datetime(2026, 10, 18, 2, 2, 0),
            "source": "gmail",
            "device": "wks-07",
            "actor": "mira.chen",
            "action": "email_sent",
            "object": "Q4-board-deck.tar.gz",
            "ip": "198.51.100.42",
            "parser_version": "gmail_json@1.1.0",
            "tz_assumption": "explicit_offset",
            "family": "gmail",
            "raw": {
                "timestamp": "Sun, 18 Oct 2026 07:32:00 +0530",
                "source_locator": "gmail:message_id=<exfil-901@corp.example>",
                "message_id": "<exfil-901@corp.example>",
                "internetMessageId": "<exfil-901@corp.example>",
                "sender": "mira.chen@corp.example",
                "recipients": ["external@drop.example"],
                "subject": "Q4-board-deck.tar.gz",
                "attachments": [{"filename": "Q4-board-deck.tar.gz", "sha256": attach_sha}],
                "attachment_sha256": attach_sha,
                "parser_confidence": 0.99,
            },
        },
        {
            "event_id": f"{case_id}:EV-03",
            "case_id": case_id,
            "evidence_id": f"{case_id}-EV-PST",
            "artifact_ref": "pst:/Top of Personal Folders/Sent Items#item_id=2097188&message_id=<exfil-901@corp.example>",
            "sha256": sha_by_evid[f"{case_id}-EV-PST"],
            "timestamp": datetime(2026, 10, 18, 2, 2, 5),
            "source": "pst",
            "device": "wks-07",
            "actor": "mira.chen",
            "action": "email_sent",
            "object": "Q4-board-deck.tar.gz",
            "ip": "198.51.100.42",
            "parser_version": "pst_parser@1.1.0",
            "tz_assumption": "explicit_offset",
            "family": "pst",
            "raw": {
                "timestamp": "2026-10-18T02:02:05Z",
                "source_locator": "pst:/Top of Personal Folders/Sent Items#item_id=2097188&message_id=<exfil-901@corp.example>",
                "folder_path": "/Top of Personal Folders/Sent Items",
                "item_id": "2097188",
                "message_id": "<exfil-901@corp.example>",
                "internetMessageId": "<exfil-901@corp.example>",
                "sender": "mira.chen@corp.example",
                "recipients": ["external@drop.example"],
                "subject": "Q4-board-deck.tar.gz",
                "attachments": [{"filename": "Q4-board-deck.tar.gz", "sha256": attach_sha}],
                "attachment_sha256": attach_sha,
                "parser_confidence": 0.99,
            },
        },
        {
            "event_id": f"{case_id}:EV-04",
            "case_id": case_id,
            "evidence_id": f"{case_id}-EV-ZEEK",
            "artifact_ref": "conn.log#uid=C9x8v7W6u5T4s3R2q1&line=2",
            "sha256": sha_by_evid[f"{case_id}-EV-ZEEK"],
            "timestamp": datetime(2026, 10, 18, 2, 4, 30),
            "source": "zeek",
            "device": "wks-07",
            "actor": "mira.chen",
            "action": "network_connection",
            "object": "drop.example",
            "ip": "198.51.100.42",
            "parser_version": "zeek_conn@1.1.0",
            "tz_assumption": "epoch_utc",
            "family": "zeek_conn",
            "raw": {
                "timestamp": "1792289070.0",
                "source_locator": "conn.log#uid=C9x8v7W6u5T4s3R2q1&line=2",
                "uid": "C9x8v7W6u5T4s3R2q1",
                "zeek_uid": "C9x8v7W6u5T4s3R2q1",
                "src_ip": "198.51.100.42",
                "dst_ip": "203.0.113.55",
                "parser_confidence": 0.95,
            },
        },
        {
            "event_id": f"{case_id}:EV-05",
            "case_id": case_id,
            "evidence_id": f"{case_id}-EV-WEB",
            "artifact_ref": "browser_history.csv#row=2",
            "sha256": sha_by_evid[f"{case_id}-EV-WEB"],
            "timestamp": datetime(2026, 10, 18, 2, 5, 0),
            "source": "browser",
            "device": "wks-07",
            "actor": "mira.chen",
            "action": "file_upload",
            "object": "https://drop.example/Q4-board-deck.tar.gz",
            "ip": "198.51.100.42",
            "parser_version": "browser_csv@1.1.0",
            "tz_assumption": "explicit_offset",
            "family": "browser_history",
            "raw": {
                "timestamp": "2026-10-18T02:05:00Z",
                "source_locator": "browser_history.csv#row=2",
                "url": "https://drop.example/Q4-board-deck.tar.gz",
                "content_hash": attach_sha,
                "sha256": attach_sha,
                "parser_confidence": 0.95,
            },
        },
    ]

    event_rows: list[EventModel] = []
    for ed in events_data:
        row = EventModel(**ed)
        session.add(row)
        event_rows.append(row)
    session.commit()

    evidence_context = {
        ev.evidence_id: {
            "status": ev.status or "ACTIVE",
            "verify_state": ev.verify_state or "VERIFIED",
            "sha256": ev.sha256,
        }
        for ev in evidence_rows
    }
    registry = load_registry()
    corr_result = correlate_case_events(
        case_id,
        [e.to_dict() for e in event_rows],
        registry,
        evidence_context=evidence_context,
    )
    relationships = [dict(r) for r in corr_result.relationships]
    return evidence_rows, event_rows, relationships


def test_phase4_immutable_analysis_run_manifest_and_continuity(db_session: Session, tmp_path: Path):
    """Phase 4: Verify all 10 required immutable analysis-run fields, immutability, and T7/T8 binding."""
    case_id = "CASE-P4-MANIFEST"
    evidence_rows, event_rows, relationships = _seed_multi_source_case(
        db_session, tmp_path, case_id=case_id
    )

    run_res = execute_analysis_run(
        db_session,
        case_id,
        assumptions={"case_timezone": "Asia/Kolkata"},
        relationships=relationships,
    )
    db_session.commit()

    run_id = run_res["run_id"]
    assert run_res["analysis_run_id"] == run_id

    # 1. Verify all 10 required Phase 4 fields on execute_analysis_run response
    required_phase4_fields = (
        "run_id",
        "case_id",
        "input_evidence_hashes",
        "parser_versions",
        "correlation_config_version",
        "module_versions",
        "started_at",
        "completed_at",
        "status",
        "output_manifest_hash",
    )
    for field_name in required_phase4_fields:
        assert field_name in run_res, f"Missing Phase 4 field {field_name!r} in execute_analysis_run output"
        assert run_res[field_name] is not None, f"Phase 4 field {field_name!r} must not be None"

    assert run_res["case_id"] == case_id
    assert run_res["status"] == "COMPLETED"
    assert len(run_res["output_manifest_hash"]) == 64
    assert len(run_res["input_evidence_hashes"]) == len(evidence_rows)
    expected_hashes = {ev.evidence_id: ev.sha256 for ev in evidence_rows}
    actual_hashes = {item["evidence_id"]: item["sha256"] for item in run_res["input_evidence_hashes"]}
    assert actual_hashes == expected_hashes

    # Parser versions captured
    assert "gmail_json@1.1.0" in run_res["parser_versions"].get("known", [])
    assert "pst_parser@1.1.0" in run_res["parser_versions"].get("known", [])
    assert "zeek_conn@1.1.0" in run_res["parser_versions"].get("known", [])
    # Correlation config version captured
    assert run_res["correlation_config_version"] == "corr-config-v1"
    # Module versions captured
    for mod_key in (
        "engine",
        "correlation_engine",
        "t6_claims_engine",
        "t7_hypothesis_engine",
        "t8_reconstruction_engine",
        "t8_immutable_runs",
    ):
        assert mod_key in run_res["module_versions"]

    # 2. Verify get_run_details returns the exact same 10 Phase 4 fields
    details = get_run_details(db_session, run_id)
    for field_name in required_phase4_fields:
        assert field_name in details, f"Missing Phase 4 field {field_name!r} in get_run_details output"
        assert details[field_name] == run_res[field_name]

    # 3. Verify T7 hypotheses and T8 reconstruction are explicitly tied to analysis_run_id
    for hyp in run_res["ranked_hypotheses"]:
        assert hyp["analysis_run_id"] == run_id
        assert hyp["case_id"] == case_id
        assert hyp["conclusion_type"] == "MACHINE_HYPOTHESIS"
        assert hyp["investigator_confirmed"] is False

    recon = run_res["reconstruction"]
    assert recon is not None
    assert recon["analysis_run_id"] == run_id
    assert recon["case_id"] == case_id
    for ev in recon["timeline_events"]:
        assert ev["analysis_run_id"] == run_id

    # 4. Verify write-once immutability of AnalysisRun and RunSnapshot
    run_row = db_session.query(AnalysisRun).filter(AnalysisRun.run_id == run_id).one()
    with pytest.raises(ImmutableRecordError, match="write-once"):
        run_row.engine_version = "tampered-engine@9.9.9"
        db_session.flush()
    db_session.expire(run_row)

    snap_row = db_session.query(RunSnapshot).filter(RunSnapshot.run_id == run_id).one()
    with pytest.raises(ImmutableRecordError, match="write-once"):
        snap_row.ranking_hash = "0" * 64
        db_session.flush()
    db_session.expire(snap_row)


def test_phase4_deterministic_reproducibility_with_relationships(db_session: Session, tmp_path: Path):
    """Phase 4: Re-running with identical inputs, relationships, and versions produces identical analytical results."""
    case_id = "CASE-P4-REPRO"
    _, _, relationships = _seed_multi_source_case(db_session, tmp_path, case_id=case_id)

    run_a = execute_analysis_run(
        db_session,
        case_id,
        assumptions={"case_timezone": "UTC"},
        relationships=relationships,
    )
    db_session.commit()

    run_b = execute_analysis_run(
        db_session,
        case_id,
        assumptions={"case_timezone": "UTC"},
        relationships=relationships,
    )
    db_session.commit()

    assert run_a["ranking_hash"] == run_b["ranking_hash"]
    assert run_a["output_manifest_hash"] == run_b["output_manifest_hash"]
    assert run_a["outcome"] == run_b["outcome"]
    assert run_a["relationships_count"] == run_b["relationships_count"]

    # Historical replay verification succeeds with 0 discrepancies
    repro = verify_run_reproducibility(db_session, run_a["run_id"])
    assert repro["verified"] is True
    assert repro["historical_replay"]["verified"] is True
    assert repro["historical_replay"]["discrepancies"] == []


def test_phase5_and_phase6_focused_end_to_end_pipeline_and_reporting_boundary(
    db_session: Session, tmp_path: Path
):
    """Phase 5 & Phase 6: End-to-end verification of:
    Evidence -> Normalised Events -> Relationships (PRIMARY & SECONDARY) ->
    T7 Hypotheses -> T8 Reconstruction -> Immutable Analysis Run -> Saiesha Report Builder.
    """
    case_id = "CASE-E2E-PIPELINE"
    evidence_rows, event_rows, corr_relationships = _seed_multi_source_case(
        db_session, tmp_path, case_id=case_id
    )

    # Also add an explicit SECONDARY relationship alongside Shambhavi's PRIMARY relationships
    secondary_rel = {
        "relationship_id": "rel_" + "c" * 64,
        "case_id": case_id,
        "source_event_id": f"{case_id}:EV-04",
        "target_event_id": f"{case_id}:EV-05",
        "relationship_type": "SECONDARY",
        "score": 0.84,
        "threshold_version": "1.0.0-provisional",
        "feature_contributions": [
            {
                "parameter_id": "P19_TEMPORAL_PROXIMITY",
                "kind": "feature",
                "value": 0.92,
                "weight": 0.12,
                "contribution": 0.1104,
            }
        ],
        "counter_signals": [],
        "explanation": "Secondary network-to-browser temporal and endpoint correlation.",
        "evidence_refs": [f"{case_id}-EV-ZEEK", f"{case_id}-EV-WEB"],
        "review_status": "HIGH_CONFIDENCE",
        "config_version": "corr-config-v1",
    }
    all_relationships = [*corr_relationships, secondary_rel]

    # Step 1: Verify evidence records exist with SHA-256 hashes and provenance metadata
    assert len(evidence_rows) == 5
    for ev in evidence_rows:
        assert len(ev.sha256) == 64
        assert ev.source_locator is not None
        assert ev.parser_version is not None

    # Step 2: Verify normalised events exist with evidence_id and source_locator
    assert len(event_rows) == 5
    for ev_row in event_rows:
        assert ev_row.evidence_id.startswith(case_id)
        assert ev_row.artifact_ref is not None

    # Step 3: Verify both PRIMARY and SECONDARY correlation relationships are present
    rel_types = {r["relationship_type"] for r in all_relationships}
    assert rel_types == {"PRIMARY", "SECONDARY"}

    # Step 4-6: Execute immutable analysis run consuming events and relationships
    run_res = execute_analysis_run(
        db_session,
        case_id,
        assumptions={"case_timezone": "Asia/Kolkata"},
        relationships=all_relationships,
    )
    db_session.commit()
    run_id = run_res["run_id"]

    # Step 4 check: T7 consumed relationships and preserved PRIMARY vs SECONDARY & evidence refs
    assert run_res["relationships_count"] == len(all_relationships)
    h1 = next(h for h in run_res["ranked_hypotheses"] if h["id"] == "H1")
    assert len(h1["primary_relationship_ids"]) >= 1
    assert secondary_rel["relationship_id"] in h1["secondary_relationship_ids"]
    assert len(h1["supporting_evidence_ids"]) >= 2
    assert h1["analysis_run_id"] == run_id

    # Step 5 check: T8 produced reconstructed timeline with source locators and chronology fields
    recon = run_res["reconstruction"]
    assert recon is not None
    assert recon["analysis_run_id"] == run_id
    assert len(recon["timeline_events"]) == 5
    locators_found = {e["source_locator"] for e in recon["timeline_events"]}
    assert "gmail:message_id=<exfil-901@corp.example>" in locators_found
    assert "conn.log#uid=C9x8v7W6u5T4s3R2q1&line=2" in locators_found

    by_ev_id = {e["event_id"]: e for e in recon["timeline_events"]}
    assert by_ev_id[f"{case_id}:EV-02"]["source_locator_details"]["message_id"] == "<exfil-901@corp.example>"
    assert by_ev_id[f"{case_id}:EV-03"]["source_locator_details"]["pst_item_id"] == "2097188"
    assert by_ev_id[f"{case_id}:EV-04"]["source_locator_details"]["zeek_uid"] == "C9x8v7W6u5T4s3R2q1"
    assert by_ev_id[f"{case_id}:EV-01"]["source_locator_details"]["line_number"] == 2
    assert by_ev_id[f"{case_id}:EV-01"]["source_locator_details"]["byte_offset"] == 64

    # Step 6 & Phase 5 Boundary 3 check: Saiesha's report builder & PDF renderer consume the run cleanly
    report_inputs = load_report_inputs(db_session, case_id, run_id)
    report_content = build_report_content(report_inputs)
    assert report_content["cover"]["case_id"] == case_id
    assert report_content["cover"]["run_id"] == run_id
    meta = {
        "report_id": "RPT-E2E-001",
        "report_version": 1,
        "generated_at": "2026-10-18T03:00:00+00:00",
        "generated_by": "Niharika Integration Verification",
        "content_hash": content_hash(report_content),
    }
    pdf_bytes = render_report_pdf(report_content, meta)
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 1000
