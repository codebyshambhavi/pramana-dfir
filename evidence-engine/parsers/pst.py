"""PST archive parser using an optional maintained pypff binding.

Pypff is not enabled silently: this parser raises an explicit limitation if the
binding is unavailable or the file is not a PST.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any
from datetime import datetime

from parsers.normalization import stable_event_id, utc_timestamp
from parsers.provenance import provenance_fields

PARSER_NAME = "pst"
PARSER_VERSION = "1.0.0"


def _safe_filename(name: object, fallback: str) -> str:
    text = str(name or fallback).strip()
    text = Path(text).name
    text = re.sub(r"[^A-Za-z0-9_.-]", "_", text)
    return text or fallback


def _attachment_bytes(attachment: Any) -> tuple[bytes, str | None]:
    """Read attachment bytes using supported pypff variants without fabricating data."""
    for method_name in ("get_data", "read"):
        method = getattr(attachment, method_name, None)
        if callable(method):
            try:
                data = method()
                if isinstance(data, bytes):
                    return data, None
                if isinstance(data, bytearray):
                    return bytes(data), None
            except Exception as exc:
                return b"", f"{method_name} failed: {type(exc).__name__}"

    read_buffer = getattr(attachment, "read_buffer", None)
    if callable(read_buffer):
        size = getattr(attachment, "size", None)
        try:
            size_int = int(size) if size is not None else 1024 * 1024
            chunks: list[bytes] = []
            remaining = size_int
            while remaining > 0:
                chunk = read_buffer(min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(bytes(chunk))
                remaining -= len(chunk)
            return b"".join(chunks), None if remaining == 0 else "read_buffer returned truncated data"
        except Exception as exc:
            return b"", f"read_buffer failed: {type(exc).__name__}"

    get_data = getattr(attachment, "get_data", None)
    if get_data is not None:
        return b"", "unsupported attachment data API"
    return b"", "attachment data API is unsupported"


def validate_pst(path: str) -> None:
    with open(path, "rb") as handle:
        magic = handle.read(4)
    if magic not in (b"!BDN", b"\x21\x42\x44\x4e"):
        raise ValueError("Invalid PST: missing !BDN archive signature")


def extract_pst_attachments(
    path: str,
    output_dir: str,
    parent_evidence_id: str | None = None,
) -> dict[str, Any]:
    """Extract supported PST attachment bytes and return forensic metadata."""
    validate_pst(path)
    try:
        import pypff
    except ImportError as exc:
        raise RuntimeError("PST attachment extraction requires the optional pypff binding") from exc

    archive = pypff.file()
    try:
        archive.open(path)
    except (IOError, OSError) as exc:
        raise ValueError(f"Cannot open PST archive: {exc}") from exc

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    attachments: list[dict[str, Any]] = []
    warnings: list[str] = []

    try:
        root = archive.get_root_folder()
        stack = [(root, "")]
        while stack:
            folder, parent = stack.pop()
            folder_name = getattr(folder, "name", "") or ""
            folder_path = f"{parent}/{folder_name}".strip("/")
            subfolders = getattr(folder, "sub_folders", [])
            for subfolder in subfolders:
                stack.append((subfolder, folder_path))
            items = getattr(folder, "sub_messages", None)
            if items is None:
                items = getattr(folder, "sub_items", [])
            for message_index, item in enumerate(items):
                message_id = getattr(item, "identifier", None)
                message_locator = f"{Path(path).name}#{folder_path}#{message_id if message_id is not None else message_index}"
                item_attachments = getattr(item, "attachments", None)
                if item_attachments is None:
                    continue
                try:
                    attachment_count = len(item_attachments)
                except Exception as exc:
                    warnings.append(f"{message_locator}: attachment list inaccessible: {type(exc).__name__}")
                    continue
                for attachment_index in range(attachment_count):
                    try:
                        attachment = item_attachments[attachment_index]
                    except Exception as exc:
                        warnings.append(
                            f"{message_locator}: attachment {attachment_index} inaccessible: {type(exc).__name__}"
                        )
                        continue
                    name = getattr(attachment, "name", None)
                    safe_name = _safe_filename(name, f"attachment-{message_index}-{attachment_index}.bin")
                    attachment_id = getattr(attachment, "identifier", None)
                    if attachment_id is None:
                        attachment_id = f"{message_index}:{attachment_index}"
                    mime_type = getattr(attachment, "mime_type", None)
                    size_declared = getattr(attachment, "size", None)
                    content, read_warning = _attachment_bytes(attachment)
                    digest = hashlib.sha256(content).hexdigest()
                    status = "ACQUIRED" if content else "EMPTY"
                    if read_warning:
                        status = "FAILED"
                        warnings.append(
                            f"{message_locator}: attachment {attachment_id} ({safe_name}) extraction failed: {read_warning}"
                        )
                    if status == "EMPTY" and not read_warning:
                        warnings.append(
                            f"{message_locator}: attachment {attachment_id} ({safe_name}) is empty"
                        )

                    stored_path: str | None = None
                    if content or status == "EMPTY":
                        stored_path = str(destination / f"{message_index:06d}-{attachment_index:06d}-{safe_name}")
                        Path(stored_path).write_bytes(content)

                    attachments.append({
                        "status": status,
                        "filename": safe_name,
                        "attachment_id": str(attachment_id),
                        "mime_type": mime_type,
                        "declared_size": size_declared,
                        "byte_size": len(content),
                        "sha256": digest,
                        "folder_path": folder_path,
                        "message_id": str(message_id) if message_id is not None else str(message_index),
                        "message_locator": message_locator,
                        "parent_evidence_id": parent_evidence_id,
                        "stored_path": stored_path,
                    })
    finally:
        archive.close()

    status = "PARTIAL" if warnings else "SUCCESS"
    if not attachments and not warnings:
        status = "SUCCESS"
    return {
        "status": status,
        "attachments": attachments,
        "warnings": warnings,
        "parser_name": PARSER_NAME,
        "parser_version": PARSER_VERSION,
    }


def parse(path: str, case_id: str, evidence_id: str, sha256: str) -> list[dict[str, Any]]:
    validate_pst(path)
    try:
        import pypff
    except ImportError as exc:
        raise RuntimeError("PST parsing requires the optional pypff binding") from exc

    archive = pypff.file()
    try:
        archive.open(path)
    except (IOError, OSError) as exc:
        raise ValueError(f"Cannot open PST archive: {exc}") from exc

    events: list[dict[str, Any]] = []
    try:
        root = archive.get_root_folder()
        stack = [(root, "")]
        while stack:
            folder, parent = stack.pop()
            folder_name = getattr(folder, "name", "") or ""
            folder_path = f"{parent}/{folder_name}".strip("/")
            subfolders = getattr(folder, "sub_folders", [])
            for subfolder in subfolders:
                stack.append((subfolder, folder_path))
            items = getattr(folder, "sub_messages", None)
            if items is None:
                items = getattr(folder, "sub_items", [])
            for index, item in enumerate(items):
                item_type = getattr(item, "type", None)
                if item_type not in (1, "Email", "Message"):
                    continue
                timestamp = getattr(item, "delivery_time", None) or getattr(item, "creation_time", None)
                if timestamp is None:
                    continue
                if isinstance(timestamp, datetime):
                    timestamp_text, assumption = utc_timestamp(timestamp)
                else:
                    timestamp_text, assumption = utc_timestamp(str(timestamp))
                attachment_metadata: list[dict[str, Any]] = []
                item_attachments = getattr(item, "attachments", None)
                if item_attachments is not None:
                    try:
                        for attachment_index in range(len(item_attachments)):
                            attachment = item_attachments[attachment_index]
                            attachment_metadata.append({
                                "attachment_id": str(
                                    getattr(attachment, "identifier", attachment_index)
                                ),
                                "filename": _safe_filename(
                                    getattr(attachment, "name", None),
                                    f"attachment-{index}-{attachment_index}.bin",
                                ),
                                "mime_type": getattr(attachment, "mime_type", None),
                                "declared_size": getattr(attachment, "size", None),
                                "extraction_status": "metadata_observed",
                            })
                    except Exception:
                        attachment_metadata.append({
                            "extraction_status": "unsupported",
                            "warning": "PST attachment metadata could not be enumerated",
                        })
                event = {
                    "event_id": stable_event_id("EV-PST", case_id, evidence_id, f"{folder_path}-{index}"),
                    "case_id": case_id,
                    "evidence_id": evidence_id,
                    "artifact_ref": f"{Path(path).name}#{folder_path}#{getattr(item, 'identifier', index)}",
                    "sha256": sha256,
                    "timestamp": timestamp_text,
                    "source": "pst",
                    "actor": getattr(item, "sender_name", None),
                    "action": "EMAIL_RECEIVED",
                    "object": getattr(item, "subject", None),
                    "raw": {
                        "folder_path": folder_path,
                        "item_identifier": getattr(item, "identifier", None),
                        "sender_name": getattr(item, "sender_name", None),
                        "subject": getattr(item, "subject", None),
                        "attachments": attachment_metadata,
                    },
                    **provenance_fields(
                        parser=PARSER_NAME,
                        version=PARSER_VERSION,
                        family="outlook_pst",
                        tz_assumption=assumption,
                    ),
                }
                events.append(event)
    finally:
        archive.close()
    return events
