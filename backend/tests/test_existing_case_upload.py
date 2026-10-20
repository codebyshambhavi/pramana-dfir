"""Test uploading evidence to a case that already has evidence."""

import hashlib
import io
import pytest
from fastapi.testclient import TestClient

def test_upload_evidence_to_existing_case_with_evidence(client):
    """Test uploading evidence to a case that already has evidence."""
    # Create a case
    case_id = "CASE-EXISTING-EVIDENCE"
    res_case = client.post("/cases", json={"name": "Existing Evidence Case", "case_id": case_id})
    assert res_case.status_code == 201

    # Create and upload first evidence
    csv_content_1 = (
        "timestamp,action,url\n"
        "2026-10-18T10:00:00Z,visit,https://example.com/page1\n"
    ).encode("utf-8")

    files_1 = {"file": ("evidence1.csv", io.BytesIO(csv_content_1), "text/csv")}
    res_upload1 = client.post(f"/cases/{case_id}/evidence", files=files_1)
    assert res_upload1.status_code == 201, f"First upload failed: {res_upload1.text}"
    upload_data1 = res_upload1.json()
    evidence_id_1 = upload_data1["evidence_id"]
    assert evidence_id_1 == "EVID-001", f"Expected EVID-001, got {evidence_id_1}"

    # Now upload second evidence to the same case
    csv_content_2 = (
        "timestamp,action,url\n"
        "2026-10-18T11:00:00Z,visit,https://example.com/page2\n"
    ).encode("utf-8")

    files_2 = {"file": ("evidence2.csv", io.BytesIO(csv_content_2), "text/csv")}
    res_upload2 = client.post(f"/cases/{case_id}/evidence", files=files_2)
    print(f"Second upload status: {res_upload2.status_code}")
    print(f"Second upload response: {res_upload2.text}")

    # This should succeed with EVID-002
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

def test_upload_same_evidence_twice(client):
    """Test uploading the exact same evidence file twice to the same case."""
    # Create a case
    case_id = "CASE-SAME-EVIDENCE-TWICE"
    res_case = client.post("/cases", json={"name": "Same Evidence Twice Case", "case_id": case_id})
    assert res_case.status_code == 201

    # Create test CSV content
    csv_content = (
        "timestamp,action,url\n"
        "2026-10-18T10:00:00Z,visit,https://example.com\n"
        "2026-10-18T10:05:00Z,click,https://example.com/page2\n"
    ).encode("utf-8")
    expected_sha256 = hashlib.sha256(csv_content).hexdigest()

    # Upload first evidence
    files_1 = {"file": ("same.csv", io.BytesIO(csv_content), "text/csv")}
    res_upload1 = client.post(f"/cases/{case_id}/evidence", files=files_1)
    assert res_upload1.status_code == 201, f"First upload failed: {res_upload1.text}"
    upload_data1 = res_upload1.json()
    evidence_id_1 = upload_data1["evidence_id"]
    assert evidence_id_1 == "EVID-001", f"Expected EVID-001, got {evidence_id_1}"

    # Upload the SAME evidence again
    files_2 = {"file": ("same.csv", io.BytesIO(csv_content), "text/csv")}
    res_upload2 = client.post(f"/cases/{case_id}/evidence", files=files_2)
    print(f"Second upload of same file status: {res_upload2.status_code}")
    print(f"Second upload of same file response: {res_upload2.text}")

    # This should succeed with EVID-002 (different evidence_id because it's a different upload)
    assert res_upload2.status_code == 201, f"Second upload failed: {res_upload2.text}"
    upload_data2 = res_upload2.json()
    evidence_id_2 = upload_data2["evidence_id"]
    assert evidence_id_2 == "EVID-002", f"Expected EVID-002, got {evidence_id_2}"

    # The SHA-256 should be the same since it's the same file
    assert upload_data1["sha256"] == upload_data2["sha256"] == expected_sha256

    # Verify both evidence records exist
    res_evidence = client.get(f"/cases/{case_id}/evidence")
    assert res_evidence.status_code == 200
    evidence_list = res_evidence.json()
    assert len(evidence_list) == 2

    returned_evidence_ids = {e["evidence_id"] for e in evidence_list}
    assert returned_evidence_ids == {"EVID-001", "EVID-002"}

if __name__ == "__main__":
    pytest.main([__file__, "-v"])