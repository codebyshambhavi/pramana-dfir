"""Test to demonstrate evidence ID generation race condition."""

import hashlib
import io
import pytest
from fastapi.testclient import TestClient

def test_sequential_evidence_upload_same_case(client):
    """Test uploading evidence twice to the same case sequentially."""
    # Create a case
    case_id = "CASE-SEQUENTIAL-TEST"
    res_case = client.post("/cases", json={"name": "Sequential Test", "case_id": case_id})
    assert res_case.status_code == 201, f"Failed to create case: {res_case.text}"

    # Create test CSV content
    csv_content = (
        "timestamp,action,url\n"
        "2026-10-18T10:00:00Z,visit,https://example.com\n"
    ).encode("utf-8")
    expected_sha256 = hashlib.sha256(csv_content).hexdigest()

    # Upload first evidence
    files_1 = {"file": ("evidence1.csv", io.BytesIO(csv_content), "text/csv")}
    res_upload1 = client.post(f"/cases/{case_id}/evidence", files=files_1)
    assert res_upload1.status_code == 201, f"First upload failed: {res_upload1.text}"
    upload_data1 = res_upload1.json()
    evidence_id_1 = upload_data1["evidence_id"]
    assert evidence_id_1 == "EVID-001", f"Expected EVID-001, got {evidence_id_1}"

    # Upload second evidence to same case
    files_2 = {"file": ("evidence2.csv", io.BytesIO(csv_content), "text/csv")}
    res_upload2 = client.post(f"/cases/{case_id}/evidence", files=files_2)
    # This should succeed with EVID-002, but might fail due to race condition
    assert res_upload2.status_code == 201, f"Second upload failed: {res_upload2.text}"
    upload_data2 = res_upload2.json()
    evidence_id_2 = upload_data2["evidence_id"]
    assert evidence_id_2 == "EVID-002", f"Expected EVID-002, got {evidence_id_2}"

    # Verify both evidence records exist
    res_evidence = client.get(f"/cases/{case_id}/evidence")
    assert res_evidence.status_code == 200
    evidence_list = res_evidence.json()
    assert len(evidence_list) == 2

    returned_evidence_ids = {e["evidence_id"] for e in evidence_list}
    assert returned_evidence_ids == {"EVID-001", "EVID-002"}