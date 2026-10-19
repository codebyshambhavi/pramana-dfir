"""Role 3 End-to-End Tests: Critical path and forensic invariants.

Critical path:
Create case -> Upload evidence -> Hash and record custody -> Store events ->
Build graph -> Analyze -> View findings and lineage -> Export PDF.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import CustodyEntry
from app.db.session import verify_custody_log


def test_case_lifecycle(client: TestClient):
    """Test case creation, retrieval, and collision handling."""
    # Create case with custom ID
    res = client.post("/cases", json={"name": "Operation Titan", "case_id": "CASE-TITAN"})
    assert res.status_code == 201
    data = res.json()
    assert data["case_id"] == "CASE-TITAN"
    assert data["name"] == "Operation Titan"

    # Duplicate creation returns 409
    res_dup = client.post("/cases", json={"name": "Operation Titan", "case_id": "CASE-TITAN"})
    assert res_dup.status_code == 409

    # Retrieve case
    res_get = client.get("/cases/CASE-TITAN")
    assert res_get.status_code == 200
    assert res_get.json()["name"] == "Operation Titan"

    # Non-existent case
    assert client.get("/cases/CASE-NONEXISTENT").status_code == 404


def test_critical_path_end_to_end(client: TestClient, db_session: Session):
    """Execute complete forensic investigation lifecycle."""
    case_id = "CASE-CRITICAL-001"
    # 1. Create Case
    res_case = client.post("/cases", json={"name": "Critical Breach Investigation", "case_id": case_id})
    assert res_case.status_code == 201

    # 2. Prepare synthetic evidence (Browser History CSV with planted items: off-hour login, archive upload)
    csv_content = (
        "url,title,timestamp,user,host,action,lat,lon\n"
        "https://portal.internal/login,Internal Portal,2026-10-18T02:30:00Z,analyst_sec,DEV-WORKSTATION-01,login,28.6139,77.2090\n"
        "https://storage.cloud/upload,Cloud Transfer,2026-10-18T02:35:00Z,analyst_sec,DEV-WORKSTATION-01,file_upload,28.6139,77.2090\n"
        "https://portal.internal/archive,Archive Manager,2026-10-18T02:32:00Z,analyst_sec,DEV-WORKSTATION-01,archive_create,28.6139,77.2090\n"
    ).encode("utf-8")
    expected_sha256 = hashlib.sha256(csv_content).hexdigest()

    # 3. Upload Evidence
    files = {"file": ("browser_history.csv", io.BytesIO(csv_content), "text/csv")}
    res_upload = client.post(f"/cases/{case_id}/evidence", files=files)
    assert res_upload.status_code == 201
    upload_data = res_upload.json()
    evidence_id = upload_data["evidence_id"]
    assert upload_data["sha256"] == expected_sha256
    assert upload_data["events_created"] >= 3

    # 4. Verify Evidence Listing & Custody Chain
    res_ev_list = client.get(f"/cases/{case_id}/evidence")
    assert res_ev_list.status_code == 200
    evidence_items = res_ev_list.json()
    assert len(evidence_items) == 1
    assert evidence_items[0]["evidence_id"] == evidence_id
    assert evidence_items[0]["sha256"] == expected_sha256
    assert len(evidence_items[0]["custody"]) >= 1

    # Check cryptographic custody verification
    is_valid, msg = verify_custody_log(db_session, evidence_id)
    assert is_valid is True
    assert "cryptographically verified" in msg

    # 5. Retrieve Stored Events with Filter
    res_events = client.get(f"/cases/{case_id}/events?source=browser")
    assert res_events.status_code == 200
    events = res_events.json()
    assert len(events) >= 3
    event_ids = [e["event_id"] for e in events]
    assert all(e["case_id"] == case_id for e in events)
    assert all(e["sha256"] == expected_sha256 for e in events)

    # 6. Build and Verify Evidence Graph
    res_graph = client.get(f"/cases/{case_id}/graph")
    assert res_graph.status_code == 200
    graph_data = res_graph.json()
    assert "nodes" in graph_data and "edges" in graph_data
    node_ids = {n["id"] for n in graph_data["nodes"]}
    assert "analyst_sec" in node_ids
    assert "DEV-WORKSTATION-01" in node_ids
    assert len(graph_data["edges"]) >= 2

    # 7. Analyze Case Events (Detect anomalies, correlations)
    res_analyze = client.post(f"/cases/{case_id}/analyze")
    assert res_analyze.status_code == 200
    assert res_analyze.json()["findings_created"] > 0

    # 8. View Findings
    res_findings = client.get(f"/cases/{case_id}/findings")
    assert res_findings.status_code == 200
    findings = res_findings.json()
    assert len(findings) > 0
    target_finding = findings[0]
    finding_id = target_finding["finding_id"]
    assert target_finding["needs_human_review"] is True
    assert target_finding["status"] == "pending"

    # 9. Review and Approve Finding
    res_patch = client.patch(f"/findings/{finding_id}", json={"status": "approved"})
    assert res_patch.status_code == 200
    assert res_patch.json() == {"finding_id": finding_id, "status": "approved"}

    # Invalid status returns 422
    res_bad_patch = client.patch(f"/findings/{finding_id}", json={"status": "invalid_status"})
    assert res_bad_patch.status_code == 422

    # 10. Check Lineage (Finding -> Events -> Evidence -> SHA-256)
    res_lineage = client.get(f"/findings/{finding_id}/lineage")
    assert res_lineage.status_code == 200
    lineage_data = res_lineage.json()
    assert lineage_data["finding_id"] == finding_id
    assert len(lineage_data["events"]) > 0
    assert len(lineage_data["evidence"]) > 0
    assert lineage_data["evidence"][0]["sha256"] == expected_sha256
    assert lineage_data["evidence"][0]["evidence_id"] == evidence_id

    # 11. Export PDF Report
    res_report = client.get(f"/cases/{case_id}/report?format=pdf")
    assert res_report.status_code == 200
    assert res_report.headers["content-type"] == "application/pdf"
    assert res_report.content.startswith(b"%PDF")
    assert len(res_report.content) > 1000
    assert "attachment" in res_report.headers.get("content-disposition", "")

    # Unsupported format returns 400
    assert client.get(f"/cases/{case_id}/report?format=docx").status_code == 400


def test_custody_tamper_detection(client: TestClient, db_session: Session):
    """Verify that tampering with an earlier custody record breaks the hash chain."""
    case_id = "CASE-TAMPER-TEST"
    client.post("/cases", json={"name": "Tamper Test", "case_id": case_id})

    # Upload evidence file
    files = {"file": ("artifact.log", io.BytesIO(b"timestamp,action\n2026-10-18T10:00:00Z,audit\n"), "text/plain")}
    res_upload = client.post(f"/cases/{case_id}/evidence", files=files)
    assert res_upload.status_code == 201
    evidence_id = res_upload.json()["evidence_id"]

    # Initial chain is intact
    is_valid, _ = verify_custody_log(db_session, evidence_id)
    assert is_valid is True

    # Tamper with the custody entry directly in DB
    entry = db_session.query(CustodyEntry).filter(CustodyEntry.evidence_id == evidence_id).first()
    assert entry is not None
    entry.actor = "Hacker Malicious Tamperer"
    db_session.commit()

    # Re-verification must fail and detect tampering
    is_valid_after, error_msg = verify_custody_log(db_session, evidence_id)
    assert is_valid_after is False
    assert "Tampered entry hash" in error_msg or "Broken chain" in error_msg


def test_openapi_spec_validity():
    """Verify that contracts/openapi.yaml is syntactically valid and covers all required paths."""
    repo_root = Path(__file__).resolve().parents[2]
    spec_path = repo_root / "contracts" / "openapi.yaml"
    assert spec_path.exists(), "contracts/openapi.yaml must exist"

    spec = yaml.safe_load(spec_path.read_text(encoding="utf-8"))
    assert spec.get("openapi") == "3.0.3"
    assert "paths" in spec

    required_endpoints = [
        "/cases",
        "/cases/{id}/evidence",
        "/cases/{id}/events",
        "/cases/{id}/graph",
        "/cases/{id}/analyze",
        "/cases/{id}/findings",
        "/findings/{id}",
        "/findings/{id}/lineage",
        "/cases/{id}/report",
    ]

    paths = spec["paths"]
    for endpoint in required_endpoints:
        assert endpoint in paths, f"Endpoint {endpoint} missing in openapi.yaml"
