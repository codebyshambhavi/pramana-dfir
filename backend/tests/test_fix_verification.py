"""Test to verify the fix for the evidence upload 500 error."""

import hashlib
import io
import pytest
from fastapi.testclient import TestClient

def test_upload_to_case_with_existing_evidence(client):
    """Test the exact scenario: upload evidence to a case that already has evidence."""
    # Simulate the user's scenario: CASE-DEMO-20261020-02 already exists
    case_id = "CASE-DEMO-20261020-02"

    # Create the case (simulating it already existing)
    res_case = client.post("/cases", json={"name": "Demo Case 2026", "case_id": case_id})
    # Might be 201 (created) or 409 (already exists) - both are fine for this test
    assert res_case.status_code in [201, 409]

    # Simulate that there's already some evidence in this case from a previous upload
    # (This would be the case in the user's scenario)
    csv_content_initial = (
        "timestamp,action,url\n"
        "2026-10-18T09:00:00Z,visit,https://example.com/initial\n"
    ).encode("utf-8")

    files_initial = {"file": ("initial.csv", io.BytesIO(csv_content_initial), "text/csv")}
    res_initial = client.post(f"/cases/{case_id}/evidence", files=files_initial)
    # This might succeed or fail depending on whether the case truly already exists
    # In the user's scenario, we assume the case exists with some evidence
    # For our test, we'll make it succeed
    if res_initial.status_code == 201:
        initial_evidence_id = res_initial.json()["evidence_id"]
        print(f"Initial evidence uploaded: {initial_evidence_id}")
    elif res_initial.status_code == 409:
        # Might be a duplicate evidence error - let's check what evidence exists
        res_evidence = client.get(f"/cases/{case_id}/evidence")
        if res_evidence.status_code == 200:
            evidence_list = res_evidence.json()
            if evidence_list:
                initial_evidence_id = evidence_list[0]["evidence_id"]
                print(f"Using existing evidence: {initial_evidence_id}")
            else:
                # No evidence exists, upload one
                res_initial = client.post(f"/cases/{case_id}/evidence", files=files_initial)
                assert res_initial.status_code == 201
                initial_evidence_id = res_initial.json()["evidence_id"]
                print(f"Initial evidence uploaded: {initial_evidence_id}")
        else:
            # Failed to get evidence list, upload one
            res_initial = client.post(f"/cases/{case_id}/evidence", files=files_initial)
            assert res_initial.status_code == 201
            initial_evidence_id = res_initial.json()["evidence_id"]
            print(f"Initial evidence uploaded: {initial_evidence_id}")
    else:
        # Some other error - for test purposes, let's just upload evidence
        res_initial = client.post(f"/cases/{case_id}/evidence", files=files_initial)
        assert res_initial.status_code == 201
        initial_evidence_id = res_initial.json()["evidence_id"]
        print(f"Initial evidence uploaded: {initial_evidence_id}")

    # NOW test the user's exact scenario:
    # Upload datasets/sample_case_001/browser_history.csv to POST /cases/{id}/evidence
    sample_csv_path = "/c/Users/Sam/Downloads/pramana-dfir/datasets/sample_case_001/browser_history.csv"

    try:
        with open(sample_csv_path, 'rb') as f:
            csv_content = f.read()
    except FileNotFoundError:
        # Fallback to creating similar content
        csv_content = (
            "timestamp,action,url,actor,device,ip\n"
            "2026-10-18T19:44:00Z,upload,https://vault.example.test/upload/CASE-001.tar.gz,mira.chen,field-laptop-07,203.0.113.42\n"
        ).encode("utf-8")

    expected_sha256 = hashlib.sha256(csv_content).hexdigest()
    print(f"Uploading file with SHA-256: {expected_sha256}")

    # This is the exact call that was returning 500 Internal Server Error
    files = {"file": ("browser_history.csv", io.BytesIO(csv_content), "text/csv")}
    res_upload = client.post(f"/cases/{case_id}/evidence", files=files)

    print(f"Upload status: {res_upload.status_code}")
    if res_upload.status_code != 201:
        print(f"Upload failed: {res_upload.text}")
        # This should NOT happen with our fix
        assert False, f"Upload failed with status {res_upload.status_code}: {res_upload.text}"

    # Verify successful upload
    upload_data = res_upload.json()
    evidence_id = upload_data["evidence_id"]
    print(f"Upload successful! Evidence ID: {evidence_id}")
    print(f"Events created: {upload_data['events_created']}")

    # Verify we can retrieve the evidence
    res_evidence = client.get(f"/cases/{case_id}/evidence")
    assert res_evidence.status_code == 200
    evidence_list = res_evidence.json()
    assert len(evidence_list) >= 1  # Should have at least our uploaded evidence

    # Verify we can retrieve the events
    res_events = client.get(f"/cases/{case_id}/events")
    assert res_events.status_code == 200
    events = res_events.json()
    assert len(events) >= upload_data["events_created"]

    # Verify event IDs are unique and properly formatted
    event_ids = [e["event_id"] for e in events]
    assert len(event_ids) == len(set(event_ids)), "Duplicate event IDs found!"

    # Verify that events belong to the correct case and their respective evidence
    # Count events for the newly uploaded evidence
    new_evidence_event_count = sum(1 for event in events if event["evidence_id"] == evidence_id)
    # Count events for the initial evidence (if we have its ID)
    initial_evidence_event_count = 0
    if 'initial_evidence_id' in locals():
        initial_evidence_event_count = sum(1 for event in events if event["evidence_id"] == initial_evidence_id)

    # Verify at least the expected number of events were created for the new evidence
    assert new_evidence_event_count >= upload_data["events_created"], \
        f"Expected at least {upload_data['events_created']} events for new evidence {evidence_id}, got {new_evidence_event_count}"

    # Verify that we can still find events from the initial evidence (if applicable)
    # This ensures we didn't corrupt existing data
    if 'initial_evidence_id' in locals() and initial_evidence_event_count > 0:
        # Verify initial evidence events still belong to initial evidence
        for event in events:
            if event["evidence_id"] == initial_evidence_id:
                assert event["case_id"] == case_id

    # Verify all events belong to the correct case
    for event in events:
        assert event["case_id"] == case_id

    print("✅ Fix verification test passed!")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])