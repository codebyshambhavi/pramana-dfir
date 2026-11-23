import base64
import os

import httpx
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import Case, ConnectorCredential, ConnectorSync, Evidence, OAuthState


def _configure_auth(monkeypatch):
    monkeypatch.setenv("PRAMANA_API_BEARER_TOKEN", "test-bearer-token")
    monkeypatch.setenv("PRAMANA_AUTHORIZED_CASE_IDS", '["CASE-CONNECTOR"]')
    monkeypatch.setenv("PRAMANA_TOKEN_ENCRYPTION_KEY", "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")


def _create_case(client):
    response = client.post("/cases", json={"name": "Connector Case", "case_id": "CASE-CONNECTOR"})
    assert response.status_code == 201


def test_connector_routes_require_authentication(client: TestClient, monkeypatch):
    _configure_auth(monkeypatch)
    _create_case(client)
    assert client.post("/cases/CASE-CONNECTOR/connectors/gmail/sync").status_code == 401
    assert client.post(
        "/cases/CASE-CONNECTOR/connectors/gmail/sync",
        headers={"Authorization": "Bearer wrong"},
    ).status_code == 401
    assert client.get(
        "/cases/CASE-CONNECTOR/connectors/gmail/callback?code=test&state=test",
    ).status_code == 401


def test_connector_case_authorisation(client: TestClient, monkeypatch):
    _configure_auth(monkeypatch)
    _create_case(client)
    response = client.post(
        "/cases/CASE-OTHER/connectors/gmail/authorise",
        headers={"Authorization": "Bearer test-bearer-token"},
    )
    assert response.status_code == 403
    callback = client.get(
        "/cases/CASE-OTHER/connectors/gmail/callback?code=test&state=test",
        headers={"Authorization": "Bearer test-bearer-token"},
    )
    assert callback.status_code == 403


def test_gmail_oauth_state_missing_mismatch_and_expiry(client: TestClient, db_session: Session, monkeypatch):
    _configure_auth(monkeypatch)
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-client")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://localhost/callback")
    _create_case(client)
    headers = {"Authorization": "Bearer test-bearer-token"}

    started = client.post("/cases/CASE-CONNECTOR/connectors/gmail/authorise", headers=headers)
    assert started.status_code == 200
    state = started.json()["authorization_url"].split("state=")[1].split("&")[0]
    assert db_session.query(OAuthState).filter_by(state=state).one().case_id == "CASE-CONNECTOR"

    missing = client.get(
        "/cases/CASE-CONNECTOR/connectors/gmail/callback?code=test",
        headers=headers,
    )
    assert missing.status_code == 400
    mismatch = client.get(
        "/cases/CASE-CONNECTOR/connectors/gmail/callback?code=test&state=wrong",
        headers=headers,
    )
    assert mismatch.status_code == 400

    from app.db.models import utc_now
    record = db_session.query(OAuthState).filter_by(state=state).one()
    record.expires_at = utc_now().replace(tzinfo=None)
    db_session.commit()
    expired = client.get(
        f"/cases/CASE-CONNECTOR/connectors/gmail/callback?code=test&state={state}",
        headers=headers,
    )
    assert expired.status_code == 400


def test_microsoft_oauth_state_mismatch(client: TestClient, db_session: Session, monkeypatch):
    _configure_auth(monkeypatch)
    monkeypatch.setenv("MICROSOFT_CLIENT_ID", "test-client")
    monkeypatch.setenv("MICROSOFT_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("MICROSOFT_REDIRECT_URI", "http://localhost/callback")
    _create_case(client)
    headers = {"Authorization": "Bearer test-bearer-token"}

    started = client.post("/cases/CASE-CONNECTOR/connectors/microsoft/authorise", headers=headers)
    assert started.status_code == 200
    mismatch = client.get(
        "/cases/CASE-CONNECTOR/connectors/microsoft/callback?code=test&state=wrong",
        headers=headers,
    )
    assert mismatch.status_code == 400


def test_gmail_sync_tracks_attachment_and_duplicate(client: TestClient, db_session: Session, monkeypatch):
    _configure_auth(monkeypatch)
    _create_case(client)
    credential = ConnectorCredential(
        credential_id="gmail-test",
        case_id="CASE-CONNECTOR",
        connector="gmail",
        account_identifier="analyst@example.test",
        access_token_encrypted=None,
        refresh_token_encrypted=None,
        expires_at=None,
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    )
    db_session.add(credential)
    db_session.commit()

    from app.routers import connectors

    monkeypatch.setattr(connectors, "_refresh_gmail", lambda db, cred: "test-access-token")

    def fake_get(url, headers, params=None):
        if url.endswith("/profile"):
            return httpx.Response(200, json={"emailAddress": "analyst@example.test"})
        if url.endswith("/messages") and "attachments" not in url:
            return httpx.Response(200, json={"messages": [{"id": "m1"}]})
        if url.endswith("/messages/m1"):
            return httpx.Response(200, json={
                "id": "m1",
                "payload": {"headers": [{"name": "Subject", "value": "Test"}], "parts": [{
                    "filename": "report.bin",
                    "body": {"attachmentId": "a1"},
                }]},
            })
        if url.endswith("/attachments/a1"):
            return httpx.Response(200, json={"data": base64.urlsafe_b64encode(b"fixture").decode().rstrip("=")})
        raise AssertionError(url)

    monkeypatch.setattr(connectors, "_http_get", fake_get)
    headers = {"Authorization": "Bearer test-bearer-token"}
    first = client.post("/cases/CASE-CONNECTOR/connectors/gmail/sync", headers=headers)
    assert first.status_code == 200
    sync = db_session.query(ConnectorSync).filter_by(connector="gmail").order_by(ConnectorSync.started_at.desc()).first()
    assert sync.status == "SUCCESS"
    assert len(sync.evidence_ids) >= 2
    evidence_ids = set(sync.evidence_ids)
    assert evidence_ids.issubset({e.evidence_id for e in db_session.query(Evidence).all()})

    second = client.post("/cases/CASE-CONNECTOR/connectors/gmail/sync", headers=headers)
    assert second.status_code == 200
    assert db_session.query(Evidence).filter(Evidence.case_id == "CASE-CONNECTOR").count() >= 2


def test_outlook_sync_tracks_attachment(client: TestClient, db_session: Session, monkeypatch):
    _configure_auth(monkeypatch)
    _create_case(client)
    db_session.add(ConnectorCredential(
        credential_id="microsoft-test",
        case_id="CASE-CONNECTOR",
        connector="microsoft",
        account_identifier="analyst@contoso.test",
        access_token_encrypted=None,
        refresh_token_encrypted=None,
        expires_at=None,
        scopes=["offline_access", "Mail.Read"],
    ))
    db_session.commit()

    from app.routers import connectors
    monkeypatch.setattr(connectors, "_refresh_microsoft", lambda db, cred: "test-access-token")

    def fake_get(url, headers, params=None):
        if url.startswith("https://graph.microsoft.com/v1.0/me/messages?$top=100"):
            return httpx.Response(200, json={"value": [{"id": "msg1"}]})
        if "/messages/msg1" in url:
            return httpx.Response(200, json={
                "id": "msg1",
                "subject": "Outlook fixture",
                "sentDateTime": "2026-10-18T10:40:00Z",
                "from": {"emailAddress": {"address": "sender@example.test"}},
                "attachments": [{
                    "@odata.type": "#microsoft.graph.fileAttachment",
                    "id": "attach1",
                    "name": "report.bin",
                    "contentBytes": base64.b64encode(b"outlook-fixture").decode(),
                }],
            })
        raise AssertionError(url)

    monkeypatch.setattr(connectors, "_http_get", fake_get)
    response = client.post(
        "/cases/CASE-CONNECTOR/connectors/microsoft/sync",
        headers={"Authorization": "Bearer test-bearer-token"},
    )
    assert response.status_code == 200
    sync = db_session.query(ConnectorSync).filter_by(connector="microsoft").one()
    assert sync.status == "SUCCESS"
    assert len(sync.evidence_ids) >= 2


def test_gmail_partial_sync_is_persisted(client: TestClient, db_session: Session, monkeypatch):
    _configure_auth(monkeypatch)
    _create_case(client)
    db_session.add(ConnectorCredential(
        credential_id="gmail-partial",
        case_id="CASE-CONNECTOR",
        connector="gmail",
        account_identifier="analyst@example.test",
        access_token_encrypted=None,
        refresh_token_encrypted=None,
        expires_at=None,
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    ))
    db_session.commit()

    from app.routers import connectors
    monkeypatch.setattr(connectors, "_refresh_gmail", lambda db, cred: "test-access-token")

    def fake_get(url, headers, params=None):
        if url.endswith("/profile"):
            return httpx.Response(200, json={"emailAddress": "analyst@example.test"})
        if url.endswith("/messages") and "attachments" not in url:
            return httpx.Response(200, json={"messages": [{"id": "m1"}]})
        raise HTTPException(status_code=503, detail="simulated provider failure")

    monkeypatch.setattr(connectors, "_http_get", fake_get)
    response = client.post(
        "/cases/CASE-CONNECTOR/connectors/gmail/sync",
        headers={"Authorization": "Bearer test-bearer-token"},
    )
    assert response.status_code == 503
    sync = db_session.query(ConnectorSync).filter_by(connector="gmail").one()
    assert sync.status == "FAILED"
