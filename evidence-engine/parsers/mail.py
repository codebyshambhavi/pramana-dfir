"""Gmail and Microsoft Graph JSON mailbox evidence parsers."""
from __future__ import annotations

import json
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any

from parsers.normalization import stable_event_id, utc_timestamp
from parsers.provenance import provenance_fields

PARSER_NAME = "mail_json"
PARSER_VERSION = "1.0.0"


def _message_text(message: dict[str, Any]) -> str:
    payload = message.get("payload")
    if isinstance(payload, dict):
        body = payload.get("body")
        if isinstance(body, dict) and isinstance(body.get("data"), str):
            import base64
            return base64.urlsafe_b64decode(body["data"] + "===").decode("utf-8", "replace")
    if isinstance(message.get("body"), dict) and isinstance(message["body"].get("content"), str):
        return message["body"]["content"]
    return message.get("bodyPreview") or message.get("snippet") or ""


def parse_gmail(path: str, case_id: str, evidence_id: str, sha256: str) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        messages = data
    elif isinstance(data, dict):
        messages = data.get("messages", [])
    else:
        raise ValueError("Invalid Gmail export: root must be an object or list")
    if not isinstance(messages, list):
        raise ValueError("Invalid Gmail export: messages must be a list")
    events: list[dict[str, Any]] = []
    for index, message in enumerate(messages, start=1):
        if not isinstance(message, dict):
            continue
        headers = {}
        if isinstance(message.get("payload"), dict):
            raw_headers = message["payload"].get("headers", [])
            if isinstance(raw_headers, list):
                headers = {
                    h.get("name", "").lower(): h.get("value", "")
                    for h in raw_headers
                    if isinstance(h, dict) and isinstance(h.get("name"), str)
                }
        sender = headers.get("from") or message.get("sender", "")
        recipients = headers.get("to") or message.get("toRecipients", "")
        timestamp = headers.get("date")
        if timestamp:
            try:
                parsed = parsedate_to_datetime(timestamp)
            except (TypeError, ValueError, OverflowError):
                parsed = None
            if parsed is not None:
                timestamp = parsed
        if not timestamp and message.get("internalDate"):
            from datetime import datetime, timezone
            try:
                timestamp = datetime.fromtimestamp(int(message["internalDate"]) / 1000, tz=timezone.utc)
            except (TypeError, ValueError, OverflowError):
                timestamp = None
        if not timestamp:
            continue
        timestamp_iso, assumption = utc_timestamp(timestamp)
        locator = f"{Path(path).name}#gmail-message={message.get('id', index)}"
        labels = message.get("labelIds", [])
        action = "EMAIL_RECEIVED" if "INBOX" in labels or not labels else "EMAIL_SENT"
        event = {
            "event_id": stable_event_id("EV-GMAIL", case_id, evidence_id, locator),
            "case_id": case_id,
            "evidence_id": evidence_id,
            "artifact_ref": locator,
            "sha256": sha256,
            "timestamp": timestamp_iso,
            "source": "gmail",
            "actor": sender or None,
            "action": action,
            "object": headers.get("subject") or message.get("subject"),
            "raw": {
                "id": message.get("id"),
                "threadId": message.get("threadId"),
                "sender": sender,
                "recipients": recipients,
                "cc": headers.get("cc"),
                "bcc": headers.get("bcc"),
                "subject": headers.get("subject") or message.get("subject"),
                "raw_headers": headers,
                "labels": labels,
                "mimeType": message.get("mimeType"),
                "body": _message_text(message),
                "attachments": message.get("attachments", []),
            },
            **provenance_fields(parser=PARSER_NAME, version=PARSER_VERSION, family="gmail_mailbox", tz_assumption=assumption),
        }
        events.append(event)
    return events


def parse_outlook(path: str, case_id: str, evidence_id: str, sha256: str) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        messages = data
    elif isinstance(data, dict):
        messages = data.get("value", data.get("messages", []))
    else:
        raise ValueError("Invalid Outlook export: root must be an object or list")
    if not isinstance(messages, list):
        raise ValueError("Invalid Outlook export: messages must be a list")
    events: list[dict[str, Any]] = []
    for index, message in enumerate(messages, start=1):
        if not isinstance(message, dict):
            continue
        timestamp = message.get("sentDateTime") or message.get("receivedDateTime")
        if not timestamp:
            continue
        timestamp_iso, assumption = utc_timestamp(timestamp)
        locator = f"{Path(path).name}#outlook-message={message.get('id', index)}"
        sender_data = message.get("from")
        sender = sender_data.get("emailAddress", {}).get("address") if isinstance(sender_data, dict) else None
        recipient_data = message.get("toRecipients", [])
        recipients = [
            r.get("emailAddress", {}).get("address")
            for r in recipient_data
            if isinstance(r, dict)
        ] if isinstance(recipient_data, list) else []
        event = {
            "event_id": stable_event_id("EV-OUTLOOK", case_id, evidence_id, locator),
            "case_id": case_id,
            "evidence_id": evidence_id,
            "artifact_ref": locator,
            "sha256": sha256,
            "timestamp": timestamp_iso,
            "source": "outlook",
            "actor": sender,
            "action": "EMAIL_RECEIVED" if message.get("receivedDateTime") else "EMAIL_SENT",
            "object": message.get("subject"),
            "raw": {
                "id": message.get("id"),
                "conversationId": message.get("conversationId"),
                "internetMessageId": message.get("internetMessageId"),
                "sender": sender,
                "recipients": recipients,
                "subject": message.get("subject"),
                "body": message.get("body"),
                "attachments": message.get("attachments", []),
                "sentDateTime": message.get("sentDateTime"),
                "receivedDateTime": message.get("receivedDateTime"),
            },
            **provenance_fields(parser=PARSER_NAME, version=PARSER_VERSION, family="outlook", tz_assumption=assumption),
        }
        events.append(event)
    return events
