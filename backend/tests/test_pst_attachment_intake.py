import hashlib
import io
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


def test_pst_attachment_is_separate_evidence_with_custody(
    client: TestClient,
    db_session: Session,
    monkeypatch,
    tmp_path: Path,
):
    from app.db.models import Case, CustodyEntry, Evidence
    from parsers import pst

    case_id = "CASE-PST-ATTACHMENTS"
    assert client.post("/cases", json={"name": "PST Case", "case_id": case_id}).status_code == 201

    attachment_bytes = b"forensic attachment bytes"
    attachment_path = tmp_path / "message-001-report.pdf"
    attachment_path.write_bytes(attachment_bytes)

    monkeypatch.setattr("app.routers.evidence.execute_parse_evidence", lambda **kwargs: [])

    def fake_extract(path, output_dir, parent_evidence_id=None):
        return {
            "status": "SUCCESS",
            "parser_name": "pst",
            "parser_version": "1.0.0",
            "warnings": [],
            "attachments": [{
                "status": "ACQUIRED",
                "filename": "report.pdf",
                "attachment_id": "a1",
                "mime_type": "application/pdf",
                "declared_size": len(attachment_bytes),
                "byte_size": len(attachment_bytes),
                "sha256": hashlib.sha256(attachment_bytes).hexdigest(),
                "folder_path": "Inbox",
                "message_id": "m1",
                "message_locator": "fixture.pst#Inbox#m1",
                "parent_evidence_id": parent_evidence_id,
                "stored_path": str(attachment_path),
            }],
        }

    monkeypatch.setattr(pst, "extract_pst_attachments", fake_extract)

    pst_bytes = b"!BDN" + b"\x00" * 32
    response = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("fixture.pst", io.BytesIO(pst_bytes), "application/vnd.ms-outlook")},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["parse_status"] == "SUCCESS"
    assert body["attachment_count"] == 1

    evidence = db_session.query(Evidence).filter(Evidence.case_id == case_id).all()
    assert len(evidence) == 2
    parent = next(item for item in evidence if item.parent_evidence_id is None)
    attachment = next(item for item in evidence if item.parent_evidence_id == parent.evidence_id)
    assert attachment.source_type == "pst_attachment"
    assert attachment.source_identifier == "a1"
    assert attachment.sha256 == hashlib.sha256(attachment_bytes).hexdigest()
    assert attachment.source_locator == "fixture.pst#Inbox#m1"
    assert attachment.evidence_id != parent.evidence_id

    custody = db_session.query(CustodyEntry).filter(
        CustodyEntry.evidence_id == attachment.evidence_id
    ).all()
    assert len(custody) == 1
    assert "PST Attachment Acquisition" in custody[0].action


def test_pst_partial_attachment_status_is_reported(
    client: TestClient,
    db_session: Session,
    monkeypatch,
):
    from parsers import pst

    case_id = "CASE-PST-PARTIAL"
    assert client.post("/cases", json={"name": "PST Partial", "case_id": case_id}).status_code == 201
    monkeypatch.setattr("app.routers.evidence.execute_parse_evidence", lambda **kwargs: [])

    def fake_extract(path, output_dir, parent_evidence_id=None):
        return {
            "status": "PARTIAL",
            "parser_name": "pst",
            "parser_version": "1.0.0",
            "warnings": ["attachment a1 extraction failed"],
            "attachments": [{
                "status": "FAILED",
                "filename": "bad.bin",
                "attachment_id": "a1",
                "mime_type": None,
                "declared_size": 10,
                "byte_size": 0,
                "sha256": hashlib.sha256(b"").hexdigest(),
                "folder_path": "Inbox",
                "message_id": "m1",
                "message_locator": "fixture.pst#Inbox#m1",
                "parent_evidence_id": parent_evidence_id,
                "stored_path": None,
            }],
        }

    monkeypatch.setattr(pst, "extract_pst_attachments", fake_extract)
    response = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("fixture.pst", io.BytesIO(b"!BDN" + b"\x00" * 32), "application/vnd.ms-outlook")},
    )
    assert response.status_code == 201
    assert response.json()["parse_status"] == "PARTIAL"
    assert response.json()["parser_warnings"]
