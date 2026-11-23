"""Gmail and Microsoft Graph evidence connector routes."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.auth import require_authenticated_case_access
from app.db.models import Case, ConnectorCredential, ConnectorSync, Entity, Evidence, EventModel, OAuthState, utc_now
from app.db.session import append_custody_record, get_db
from app.services.pipeline import execute_parse_evidence

router = APIRouter(tags=["connectors"])
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./data/uploads"))


def _missing(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise HTTPException(status_code=503, detail=f"{name} is not configured")
    return value


def _fernet():
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="cryptography is required for secure OAuth credential storage") from exc
    key = _missing("PRAMANA_TOKEN_ENCRYPTION_KEY")
    try:
        return Fernet(key.encode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=503, detail="PRAMANA_TOKEN_ENCRYPTION_KEY is not a valid Fernet key") from exc


def _encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def _decrypt(value: str) -> str:
    return _fernet().decrypt(value.encode("ascii")).decode("utf-8")


def _get_case(db: Session, case_id: str) -> Case:
    case = db.query(Case).filter(Case.case_id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail=f"Case '{case_id}' not found")
    return case


def _credential(db: Session, case_id: str, connector: str) -> ConnectorCredential:
    credential = (
        db.query(ConnectorCredential)
        .filter(ConnectorCredential.case_id == case_id, ConnectorCredential.connector == connector)
        .first()
    )
    if not credential:
        raise HTTPException(status_code=401, detail=f"{connector} account is not authorised")
    return credential


def _refresh_gmail(db: Session, credential: ConnectorCredential) -> str:
    if credential.expires_at and credential.expires_at.replace(tzinfo=timezone.utc) > utc_now():
        if credential.access_token_encrypted:
            return _decrypt(credential.access_token_encrypted)
    if not credential.refresh_token_encrypted:
        raise HTTPException(status_code=401, detail="Gmail refresh token is unavailable")
    response = _http_post_token(
        "https://oauth2.googleapis.com/token",
        {
            "client_id": _missing("GOOGLE_CLIENT_ID"),
            "client_secret": _missing("GOOGLE_CLIENT_SECRET"),
            "refresh_token": _decrypt(credential.refresh_token_encrypted),
            "grant_type": "refresh_token",
        },
    )
    token = response.json()
    credential.access_token_encrypted = _encrypt(token["access_token"])
    credential.expires_at = utc_now() + timedelta(seconds=int(token.get("expires_in", 3600)))
    db.flush()
    return token["access_token"]


def _refresh_microsoft(db: Session, credential: ConnectorCredential) -> str:
    if credential.expires_at and credential.expires_at.replace(tzinfo=timezone.utc) > utc_now():
        if credential.access_token_encrypted:
            return _decrypt(credential.access_token_encrypted)
    if not credential.refresh_token_encrypted:
        raise HTTPException(status_code=401, detail="Microsoft refresh token is unavailable")
    tenant = os.getenv("MICROSOFT_TENANT_ID", "common")
    response = _http_post_token(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        {
            "client_id": _missing("MICROSOFT_CLIENT_ID"),
            "client_secret": _missing("MICROSOFT_CLIENT_SECRET"),
            "refresh_token": _decrypt(credential.refresh_token_encrypted),
            "grant_type": "refresh_token",
            "scope": "offline_access Mail.Read",
        },
    )
    token = response.json()
    credential.access_token_encrypted = _encrypt(token["access_token"])
    if token.get("refresh_token"):
        credential.refresh_token_encrypted = _encrypt(token["refresh_token"])
    credential.expires_at = utc_now() + timedelta(seconds=int(token.get("expires_in", 3600)))
    db.flush()
    return token["access_token"]


def _next_evidence_id(db: Session) -> str:
    """Generate an evidence ID without relying on a race-prone count."""
    while True:
        evidence_id = f"EVID-{uuid.uuid4().hex[:16].upper()}"
        if db.query(Evidence).filter(Evidence.evidence_id == evidence_id).first() is None:
            return evidence_id


def _http_get(url: str, headers: dict[str, str], params: dict[str, Any] | None = None) -> httpx.Response:
    last_error: Exception | None = None
    with httpx.Client(timeout=30.0) as client:
        for attempt in range(4):
            try:
                response = client.get(url, headers=headers, params=params)
                if response.status_code == 429:
                    raise httpx.HTTPStatusError("rate limited", request=response.request, response=response)
                response.raise_for_status()
                return response
            except (httpx.HTTPStatusError, httpx.TransportError) as exc:
                last_error = exc
                if getattr(exc, "response", None) is not None and exc.response.status_code not in (429, 500, 502, 503, 504):
                    raise
                time.sleep(min(8, 2 ** attempt))
    raise HTTPException(status_code=502, detail=f"Connector request failed after retries: {last_error}")


def _http_post_token(url: str, data: dict[str, str]) -> httpx.Response:
    last_error: Exception | None = None
    with httpx.Client(timeout=30.0) as client:
        for attempt in range(4):
            try:
                response = client.post(url, data=data)
                if response.status_code == 429:
                    raise httpx.HTTPStatusError("rate limited", request=response.request, response=response)
                response.raise_for_status()
                return response
            except (httpx.HTTPStatusError, httpx.TransportError) as exc:
                last_error = exc
                if getattr(exc, "response", None) is not None and exc.response.status_code not in (429, 500, 502, 503, 504):
                    raise
                time.sleep(min(8, 2 ** attempt))
    raise HTTPException(status_code=502, detail=f"OAuth token request failed after retries: {last_error}")


def _store_artifact(db: Session, case_id: str, filename: str, content: bytes, source: str) -> tuple[Evidence | None, bool]:
    sha256 = hashlib.sha256(content).hexdigest()
    duplicate = (
        db.query(Evidence)
        .filter(Evidence.case_id == case_id, Evidence.sha256 == sha256)
        .first()
    )
    if duplicate:
        append_custody_record(
            db=db,
            evidence_id=duplicate.evidence_id,
            actor="Authorised Connector",
            action="Duplicate evidence acquisition observed",
            sha256=sha256,
            previous_state=duplicate.status or "ACTIVE",
            new_state=duplicate.status or "ACTIVE",
            reason=f"Retry returned existing SHA-256 for {source}; original bytes and evidence ID preserved",
        )
        return duplicate, True

    target_dir = (UPLOAD_DIR / case_id).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    safe_name = Path(filename).name or "evidence.bin"
    stored_path = target_dir / f"{uuid.uuid4().hex}_{safe_name}"
    stored_path.write_bytes(content)

    evidence = Evidence(
        evidence_id=_next_evidence_id(db),
        case_id=case_id,
        filename=safe_name,
        sha256=sha256,
        size_bytes=len(content),
        intake_time=utc_now(),
        stored_path=str(stored_path),
    )
    db.add(evidence)
    db.flush()
    append_custody_record(
        db=db,
        evidence_id=evidence.evidence_id,
        actor="Authorised Connector",
        action=f"Evidence Acquisition via {source}",
        sha256=sha256,
        previous_state=None,
        new_state="ACTIVE",
        reason=f"Acquired from authorised {source} connection",
    )
    return evidence, False


def _store_export_events(db: Session, case_id: str, evidence: Evidence, export_path: str) -> int:
    parsed = execute_parse_evidence(path=export_path, case_id=case_id, evidence_id=evidence.evidence_id, sha256=evidence.sha256)
    seen_entity_ids: set[str] = set()
    for ev in parsed:
        ts = datetime.fromisoformat(ev["timestamp"].replace("Z", "+00:00"))
        db.add(EventModel(
            event_id=hashlib.sha256(f"{case_id}|{evidence.evidence_id}|{ev['event_id']}".encode()).hexdigest()[:16] + ":" + ev["event_id"],
            case_id=case_id,
            evidence_id=evidence.evidence_id,
            artifact_ref=ev["artifact_ref"],
            sha256=evidence.sha256,
            timestamp=ts,
            source=ev["source"],
            device=ev.get("device"),
            actor=ev.get("actor"),
            action=ev["action"],
            object=ev.get("object"),
            ip=ev.get("ip"),
            location=ev.get("location"),
            raw=ev.get("raw"),
            parser_version=ev.get("parser_version"),
            tz_assumption=ev.get("tz_assumption"),
            family=ev.get("family"),
        ))
        import sys
        evidence_engine_dir = str(Path(__file__).resolve().parents[3] / "evidence-engine")
        if evidence_engine_dir not in sys.path:
            sys.path.insert(0, evidence_engine_dir)
        from parsers.normalization import extract_entities
        for entity in extract_entities(ev.get("actor"), ev.get("object"), ev.get("ip"), ev.get("raw")):
            entity_id = hashlib.sha256(
                f"{case_id}|{evidence.evidence_id}|{entity['entity_type']}|{entity['canonical_value']}".encode()
            ).hexdigest()[:16]
            if entity_id in seen_entity_ids:
                continue
            seen_entity_ids.add(entity_id)
            db.add(Entity(
                entity_id=entity_id,
                case_id=case_id,
                evidence_id=evidence.evidence_id,
                entity_type=entity["entity_type"],
                canonical_value=entity["canonical_value"],
                aliases=entity["aliases"],
                normalisation_method=entity["normalisation_method"],
                confidence=entity["confidence"],
            ))
    return len(parsed)


@router.post("/cases/{case_id}/connectors/gmail/authorise")
def gmail_authorise(
    case_id: str,
    db: Session = Depends(get_db),
    principal: dict[str, Any] = Depends(require_authenticated_case_access),
) -> dict[str, str]:
    _get_case(db, case_id)
    client_id = _missing("GOOGLE_CLIENT_ID")
    redirect_uri = _missing("GOOGLE_REDIRECT_URI")
    state = secrets.token_urlsafe(32)
    db.add(OAuthState(
        state=state,
        case_id=case_id,
        connector="gmail",
        actor=principal["actor"],
        expires_at=utc_now() + timedelta(minutes=10),
    ))
    db.commit()
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    query = httpx.QueryParams(params)
    return {"authorization_url": f"https://accounts.google.com/o/oauth2/v2/auth?{query}", "state": state}


@router.get("/cases/{case_id}/connectors/gmail/callback")
def gmail_callback(
    case_id: str,
    code: str = Query(...),
    db: Session = Depends(get_db),
    state: str | None = Query(default=None),
    principal: dict[str, Any] = Depends(require_authenticated_case_access),
) -> dict[str, Any]:
    _get_case(db, case_id)
    if not state:
        raise HTTPException(status_code=400, detail="OAuth state is missing")
    oauth_state = db.query(OAuthState).with_for_update().filter(
        OAuthState.state == state,
        OAuthState.case_id == case_id,
        OAuthState.connector == "gmail",
    ).first()
    if oauth_state is None:
        raise HTTPException(status_code=400, detail="OAuth state is invalid")
    expires_at = oauth_state.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= utc_now():
        db.delete(oauth_state)
        db.commit()
        raise HTTPException(status_code=400, detail="OAuth state has expired")
    if oauth_state.consumed_at is not None:
        raise HTTPException(status_code=400, detail="OAuth state has already been consumed")
    oauth_state.consumed_at = utc_now()
    redirect_uri = _missing("GOOGLE_REDIRECT_URI")
    response = _http_post_token(
        "https://oauth2.googleapis.com/token",
        {
            "code": code,
            "client_id": _missing("GOOGLE_CLIENT_ID"),
            "client_secret": _missing("GOOGLE_CLIENT_SECRET"),
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
    )
    token = response.json()
    expires_at = utc_now() + timedelta(seconds=int(token.get("expires_in", 3600)))
    credential = ConnectorCredential(
        credential_id=uuid.uuid4().hex,
        case_id=case_id,
        connector="gmail",
        account_identifier="gmail-authorised-account",
        access_token_encrypted=_encrypt(token["access_token"]),
        refresh_token_encrypted=_encrypt(token["refresh_token"]) if token.get("refresh_token") else None,
        expires_at=expires_at,
        scopes=["https://www.googleapis.com/auth/gmail.readonly"],
    )
    db.add(credential)
    db.commit()
    return {"status": "authorised", "case_id": case_id, "connector": "gmail", "scopes": credential.scopes}


@router.post("/cases/{case_id}/connectors/gmail/sync")
def gmail_sync(
    case_id: str,
    db: Session = Depends(get_db),
    principal: dict[str, Any] = Depends(require_authenticated_case_access),
) -> dict[str, Any]:
    _get_case(db, case_id)
    credential = _credential(db, case_id, "gmail")
    sync = ConnectorSync(sync_id=uuid.uuid4().hex, case_id=case_id, connector="gmail", status="RUNNING", started_at=utc_now())
    db.add(sync)
    db.flush()
    artifact_evidence_ids: list[str] = []
    partial_warnings: list[str] = []
    try:
        access_token = _refresh_gmail(db, credential)
    except HTTPException as exc:
        sync.status = "FAILED"
        sync.warnings = [str(exc.detail)]
        sync.evidence_ids = []
        db.commit()
        raise
    if not access_token:
        sync.status = "FAILED"
        sync.warnings = ["No access token was stored"]
        db.commit()
        raise HTTPException(status_code=401, detail="Gmail access token is unavailable")

    headers = {"Authorization": f"Bearer {access_token}"}
    try:
        profile = _http_get("https://gmail.googleapis.com/gmail/v1/users/me/profile", headers)
        credential.account_identifier = profile.json().get("emailAddress") or credential.account_identifier
    except HTTPException:
        pass
    messages: list[dict[str, Any]] = []
    page_token: str | None = None
    try:
        while True:
            params: dict[str, Any] = {"maxResults": 100}
            if page_token:
                params["pageToken"] = page_token
            listing = _http_get("https://gmail.googleapis.com/gmail/v1/users/me/messages", headers, params)
            data = listing.json()
            for item in data.get("messages", []):
                detail = _http_get(
                    f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{item['id']}",
                    headers,
                    {"format": "full"},
                )
                message = detail.json()
                messages.append(message)
                def acquire_parts(parts: list[dict[str, Any]]) -> None:
                    for part in parts:
                        attachment_id = part.get("body", {}).get("attachmentId")
                        if attachment_id:
                            attachment = _http_get(
                                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{item['id']}/attachments/{attachment_id}",
                                headers,
                            )
                            encoded = attachment.json().get("data")
                            if encoded:
                                import base64
                                content = base64.urlsafe_b64decode(encoded + "===")
                                filename = part.get("filename") or f"{item['id']}-{attachment_id}.bin"
                                attachment_evidence, duplicate = _store_artifact(db, case_id, filename, content, "gmail")
                                if attachment_evidence:
                                    artifact_evidence_ids.append(attachment_evidence.evidence_id)
                                part["download_status"] = "ACQUIRED"
                                part["sha256"] = hashlib.sha256(content).hexdigest()
                                part["evidence_id"] = attachment_evidence.evidence_id if attachment_evidence else None
                                part["duplicate"] = duplicate
                            else:
                                part["download_status"] = "FAILED"
                                partial_warnings.append(
                                    f"Gmail attachment download missing data: message={item['id']} attachment={attachment_id}"
                                )
                        nested = part.get("parts")
                        if isinstance(nested, list):
                            acquire_parts(nested)
                payload = message.get("payload")
                if isinstance(payload, dict):
                    parts = payload.get("parts")
                    if isinstance(parts, list):
                        acquire_parts(parts)
            page_token = data.get("nextPageToken")
            if not page_token:
                break
    except HTTPException as exc:
        sync.status = "FAILED"
        sync.warnings = [str(exc.detail)]
        sync.evidence_ids = list(dict.fromkeys(artifact_evidence_ids))
        db.commit()
        raise
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        sync.status = "FAILED"
        sync.warnings = [f"Malformed Gmail provider response: {type(exc).__name__}"]
        sync.evidence_ids = list(dict.fromkeys(artifact_evidence_ids))
        db.commit()
        raise HTTPException(status_code=502, detail="Malformed Gmail provider response") from exc

    export = json.dumps({"messages": messages}, ensure_ascii=False, indent=2).encode("utf-8")
    evidence, duplicate_export = _store_artifact(db, case_id, f"gmail-sync-{utc_now().strftime('%Y%m%dT%H%M%SZ')}.gmail.json", export, "gmail")
    events_created = 0
    if evidence and not duplicate_export:
        try:
            events_created = _store_export_events(db, case_id, evidence, evidence.stored_path)
        except (ValueError, RuntimeError, KeyError, TypeError, json.JSONDecodeError) as exc:
            partial_warnings.append(f"Gmail export parsing failed: {exc}")
    sync.status = "PARTIAL" if partial_warnings else "SUCCESS"
    sync.completed_at = utc_now()
    sync.last_successful_sync = sync.completed_at if not partial_warnings else None
    sync.next_page_token = page_token
    sync.connected_account = credential.account_identifier
    if evidence:
        artifact_evidence_ids.append(evidence.evidence_id)
    sync.evidence_ids = list(dict.fromkeys(artifact_evidence_ids))
    sync.warnings = partial_warnings
    db.commit()
    db.refresh(sync)
    return {"sync": sync.to_dict(), "messages_acquired": len(messages), "events_created": events_created}


@router.post("/cases/{case_id}/connectors/microsoft/authorise")
def microsoft_authorise(
    case_id: str,
    db: Session = Depends(get_db),
    principal: dict[str, Any] = Depends(require_authenticated_case_access),
) -> dict[str, str]:
    _get_case(db, case_id)
    tenant = os.getenv("MICROSOFT_TENANT_ID", "common")
    client_id = _missing("MICROSOFT_CLIENT_ID")
    redirect_uri = _missing("MICROSOFT_REDIRECT_URI")
    state = secrets.token_urlsafe(32)
    db.add(OAuthState(
        state=state,
        case_id=case_id,
        connector="microsoft",
        actor=principal["actor"],
        expires_at=utc_now() + timedelta(minutes=10),
    ))
    db.commit()
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": "offline_access Mail.Read",
        "state": state,
    }
    query = httpx.QueryParams(params)
    return {"authorization_url": f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?{query}", "state": state}


@router.get("/cases/{case_id}/connectors/microsoft/callback")
def microsoft_callback(
    case_id: str,
    code: str = Query(...),
    db: Session = Depends(get_db),
    state: str | None = Query(default=None),
    principal: dict[str, Any] = Depends(require_authenticated_case_access),
) -> dict[str, Any]:
    _get_case(db, case_id)
    if not state:
        raise HTTPException(status_code=400, detail="OAuth state is missing")
    oauth_state = db.query(OAuthState).with_for_update().filter(
        OAuthState.state == state,
        OAuthState.case_id == case_id,
        OAuthState.connector == "microsoft",
    ).first()
    if oauth_state is None:
        raise HTTPException(status_code=400, detail="OAuth state is invalid")
    expires_at = oauth_state.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= utc_now():
        db.delete(oauth_state)
        db.commit()
        raise HTTPException(status_code=400, detail="OAuth state has expired")
    if oauth_state.consumed_at is not None:
        raise HTTPException(status_code=400, detail="OAuth state has already been consumed")
    oauth_state.consumed_at = utc_now()
    tenant = os.getenv("MICROSOFT_TENANT_ID", "common")
    redirect_uri = _missing("MICROSOFT_REDIRECT_URI")
    response = _http_post_token(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        {
            "client_id": _missing("MICROSOFT_CLIENT_ID"),
            "client_secret": _missing("MICROSOFT_CLIENT_SECRET"),
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
    )
    token = response.json()

    expires_at = utc_now() + timedelta(seconds=int(token.get("expires_in", 3600)))
    credential = ConnectorCredential(
        credential_id=uuid.uuid4().hex,
        case_id=case_id,
        connector="microsoft",
        account_identifier="microsoft-authorised-account",
        access_token_encrypted=_encrypt(token["access_token"]),
        refresh_token_encrypted=_encrypt(token["refresh_token"]) if token.get("refresh_token") else None,
        expires_at=expires_at,
        scopes=["offline_access", "Mail.Read"],
    )
    db.add(credential)
    db.commit()
    return {"status": "authorised", "case_id": case_id, "connector": "microsoft", "scopes": credential.scopes}


@router.post("/cases/{case_id}/connectors/microsoft/sync")
def microsoft_sync(
    case_id: str,
    db: Session = Depends(get_db),
    principal: dict[str, Any] = Depends(require_authenticated_case_access),
) -> dict[str, Any]:
    _get_case(db, case_id)
    credential = _credential(db, case_id, "microsoft")
    sync = ConnectorSync(sync_id=uuid.uuid4().hex, case_id=case_id, connector="microsoft", status="RUNNING", started_at=utc_now())
    db.add(sync)
    db.flush()
    artifact_evidence_ids: list[str] = []
    partial_warnings: list[str] = []
    try:
        access_token = _refresh_microsoft(db, credential)
    except HTTPException as exc:
        sync.status = "FAILED"
        sync.warnings = [str(exc.detail)]
        sync.evidence_ids = []
        db.commit()
        raise
    if not access_token:
        sync.status = "FAILED"
        sync.warnings = ["No access token was stored"]
        db.commit()
        raise HTTPException(status_code=401, detail="Microsoft access token is unavailable")

    headers = {"Authorization": f"Bearer {access_token}"}
    messages: list[dict[str, Any]] = []
    next_url: str | None = "https://graph.microsoft.com/v1.0/me/messages?$top=100"
    try:
        while next_url:
            response = _http_get(next_url, headers)
            data = response.json()
            for message in data.get("value", []):
                message_id = message.get("id")
                if not message_id:
                    continue
                detail = _http_get(
                    f"https://graph.microsoft.com/v1.0/me/messages/{message_id}",
                    headers,
                    {"$expand": "attachments"},
                )
                full_message = detail.json()
                messages.append(full_message)
                for attachment in full_message.get("attachments", []):
                    attachment_id = attachment.get("id")
                    if not attachment_id:
                        continue
                    if attachment.get("@odata.type", "").endswith("fileAttachment"):
                        encoded = attachment.get("contentBytes")
                        if encoded:
                            import base64
                            content = base64.b64decode(encoded)
                            filename = attachment.get("name") or f"{message_id}-{attachment_id}.bin"
                            attachment_evidence, duplicate = _store_artifact(db, case_id, filename, content, "microsoft_graph")
                            if attachment_evidence:
                                artifact_evidence_ids.append(attachment_evidence.evidence_id)
                            attachment["downloadStatus"] = "ACQUIRED"
                            attachment["sha256"] = hashlib.sha256(content).hexdigest()
                            attachment["evidence_id"] = attachment_evidence.evidence_id if attachment_evidence else None
                            attachment["duplicate"] = duplicate
                        else:
                            attachment["downloadStatus"] = "FAILED"
                            partial_warnings.append(
                                f"Microsoft attachment download missing content: message={message_id} attachment={attachment_id}"
                            )
            next_url = data.get("@odata.nextLink")
    except HTTPException as exc:
        sync.status = "FAILED"
        sync.warnings = [str(exc.detail)]
        sync.evidence_ids = list(dict.fromkeys(artifact_evidence_ids))
        db.commit()
        raise
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        sync.status = "FAILED"
        sync.warnings = [f"Malformed Microsoft Graph response: {type(exc).__name__}"]
        sync.evidence_ids = list(dict.fromkeys(artifact_evidence_ids))
        db.commit()
        raise HTTPException(status_code=502, detail="Malformed Microsoft Graph response") from exc

    export = json.dumps({"value": messages}, ensure_ascii=False, indent=2).encode("utf-8")
    evidence, duplicate_export = _store_artifact(db, case_id, f"outlook-sync-{utc_now().strftime('%Y%m%dT%H%M%SZ')}.outlook.json", export, "microsoft_graph")
    events_created = 0
    if evidence and not duplicate_export:
        try:
            events_created = _store_export_events(db, case_id, evidence, evidence.stored_path)
        except (ValueError, RuntimeError, KeyError, TypeError, json.JSONDecodeError) as exc:
            partial_warnings.append(f"Microsoft export parsing failed: {exc}")
    sync.status = "PARTIAL" if partial_warnings else "SUCCESS"
    sync.completed_at = utc_now()
    sync.last_successful_sync = sync.completed_at if not partial_warnings else None
    sync.connected_account = credential.account_identifier
    if evidence:
        artifact_evidence_ids.append(evidence.evidence_id)
    sync.evidence_ids = list(dict.fromkeys(artifact_evidence_ids))
    sync.warnings = partial_warnings
    db.commit()
    db.refresh(sync)
    return {"sync": sync.to_dict(), "messages_acquired": len(messages), "events_created": events_created}
