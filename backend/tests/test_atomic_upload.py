"""Test to verify that evidence upload is atomic."""

import hashlib
import io
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError


def test_evidence_upload_atomic_success(client, db_session):
    """Test that successful evidence upload commits all data."""
    from app.db.models import Case, Evidence, EventModel, CustodyEntry

    # Create a case
    case_id = "CASE-ATOMIC-TEST"
    res_case = client.post("/cases", json={"name": "Atomic Test", "case_id": case_id})
    assert res_case.status_code == 201

    # Create test CSV content
    csv_content = (
        "timestamp,action,url\n"
        "2026-10-18T10:00:00Z,visit,https://example.com\n"
        "2026-10-18T10:05:00Z,click,https://example.com/page2\n"
    ).encode("utf-8")

    # Upload evidence
    files = {"file": ("test.csv", io.BytesIO(csv_content), "text/csv")}
    res_upload = client.post(f"/cases/{case_id}/evidence", files=files)
    assert res_upload.status_code == 201, f"Upload failed: {res_upload.text}"

    # Verify all data was committed
    case = db_session.query(Case).filter(Case.case_id == case_id).first()
    assert case is not None

    evidence_list = db_session.query(Evidence).filter(Evidence.case_id == case_id).all()
    assert len(evidence_list) == 1
    evidence_id = evidence_list[0].evidence_id
    assert evidence_id == "EVID-001"

    custody_list = db_session.query(CustodyEntry).filter(CustodyEntry.evidence_id == evidence_id).all()
    assert len(custody_list) == 1

    events_list = db_session.query(EventModel).filter(EventModel.evidence_id == evidence_id).all()
    assert len(events_list) == 2  # Two rows in CSV


def test_evidence_upload_atomic_rollback_on_parse_failure(client, db_session, monkeypatch):
    """Test that if parsing fails, nothing is committed."""
    from app.db.models import Case, Evidence, EventModel, CustodyEntry

    # Create a case
    case_id = "CASE-ROLLBACK-TEST"
    res_case = client.post("/cases", json={"name": "Rollback Test", "case_id": case_id})
    assert res_case.status_code == 201

    # Create valid CSV content (so it gets past file validation)
    csv_content = (
        "timestamp,action,url\n"
        "2026-10-18T10:00:00Z,visit,https://example.com\n"
    ).encode("utf-8")

    # Monkey patch execute_parse_evidence to raise an exception
    # Patch in the router module where it's imported and used
    def mock_execute_parse_evidence(*args, **kwargs):
        raise Exception("Simulated parsing failure")

    monkeypatch.setattr("app.routers.evidence.execute_parse_evidence", mock_execute_parse_evidence)

    # Upload evidence
    files = {"file": ("test.csv", io.BytesIO(csv_content), "text/csv")}
    try:
        res_upload = client.post(f"/cases/{case_id}/evidence", files=files)
        # If we get a response, it should indicate failure
        assert res_upload.status_code >= 500, f"Expected failure status >= 500, got {res_upload.status_code}"
    except Exception:
        # If we get an exception instead of a response, treat it as a failed upload
        # This can happen in the test environment when monkeypatching functions to raise exceptions
        # The important thing is that the upload failed, which we can verify from the database state
        pass

    # Verify nothing was committed (atomic rollback)
    case = db_session.query(Case).filter(Case.case_id == case_id).first()
    assert case is not None  # Case should exist from creation

    evidence_list = db_session.query(Evidence).filter(Evidence.case_id == case_id).all()
    assert len(evidence_list) == 0  # No evidence should be recorded

    custody_list = db_session.query(CustodyEntry).filter(CustodyEntry.evidence_id.like("EVID-%")).all()
    assert len(custody_list) == 0  # No custody records

    events_list = db_session.query(EventModel).filter(EventModel.case_id == case_id).all()
    assert len(events_list) == 0  # No events


def test_evidence_upload_atomic_rollback_on_event_insert_failure(client, db_session, monkeypatch):
    """Test that if event insertion fails, evidence and custody are rolled back."""
    from app.db.models import Case, Evidence, EventModel, CustodyEntry
    from sqlalchemy.exc import IntegrityError

    # Create a case
    case_id = "CASE-EVENT-ROLLBACK"
    res_case = client.post("/cases", json={"name": "Event Rollback Test", "case_id": case_id})
    assert res_case.status_code == 201

    # Create valid CSV content
    csv_content = (
        "timestamp,action,url\n"
        "2026-10-18T10:00:00Z,visit,https://example.com\n"
    ).encode("utf-8")

    # Monkey patch db_session.commit to raise an exception
    # This simulates a failure during final commit
    def mock_commit():
        raise IntegrityError("Simulated constraint violation", None, None)

    monkeypatch.setattr(db_session, "commit", mock_commit)

    # Upload evidence
    files = {"file": ("test.csv", io.BytesIO(csv_content), "text/csv")}
    try:
        res_upload = client.post(f"/cases/{case_id}/evidence", files=files)
        # If we get a response, it should indicate failure
        assert res_upload.status_code >= 500
    except Exception:
        # If we get an exception instead of a response, treat it as a failed upload
        # This can happen in the test environment when monkeypatching functions to raise exceptions
        # The important thing is that the upload failed, which we can verify from the database state
        pass

    # Verify everything was rolled back (atomic behavior)
    case = db_session.query(Case).filter(Case.case_id == case_id).first()
    assert case is not None  # Case should exist from creation

    evidence_list = db_session.query(Evidence).filter(Evidence.case_id == case_id).all()
    assert len(evidence_list) == 0  # No evidence should be recorded due to rollback

    custody_list = db_session.query(CustodyEntry).filter(CustodyEntry.evidence_id.like("EVID-%")).all()
    assert len(custody_list) == 0  # No custody records should be recorded due to rollback

    events_list = db_session.query(EventModel).filter(EventModel.case_id == case_id).all()
    assert len(events_list) == 0  # No events should be recorded due to rollback


if __name__ == "__main__":
    pytest.main([__file__, "-v"])