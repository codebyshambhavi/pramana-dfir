"""Canonical, provenance-aware resolver for the correlation registry fields."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import getaddresses
from typing import Any, Mapping
from urllib.parse import urlparse

from ..entities import (extract_content_hash, normalize_actor, normalize_device,
                        normalize_file_object, normalize_ip)
from ..timeline import SourceClock, TimeInterval, effective_interval

PLACEHOLDERS = {"", "unknown", "none", "null", "n/a", "na", "-", "--", "not available", "undefined"}
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)
IP_RE = re.compile(r"^\[?[0-9a-f:.]+\]?$", re.I)

@dataclass(frozen=True)
class ResolvedField:
    name: str
    value: Any = None
    status: str = "MISSING"  # PRESENT / MISSING / INVALID
    source_locator: str | None = None

    @property
    def present(self) -> bool:
        return self.status == "PRESENT"


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _get(event: Mapping[str, Any], *paths: str) -> tuple[Any, str | None]:
    for path in paths:
        cur: Any = event
        # Parser payloads (notably Zeek) legitimately use literal dotted keys.
        if isinstance(cur, Mapping) and path in cur and cur[path] is not None:
            return cur[path], path
        parts = path.split(".")
        ok = True
        for n, part in enumerate(parts):
            if isinstance(cur, Mapping) and part in cur:
                cur = cur[part]
            elif isinstance(cur, Mapping) and ".".join(parts[n:]) in cur:
                cur = cur[".".join(parts[n:])]
                break
            else:
                ok = False; break
        if ok and cur is not None:
            return cur, path
    return None, None


def _clean_scalar(value: Any) -> Any:
    if isinstance(value, str):
        v = value.strip()
        return None if v.casefold() in PLACEHOLDERS else v
    return value


def _emails(value: Any) -> tuple[str, ...]:
    if value is None: return ()
    vals = value if isinstance(value, (list, tuple, set)) else [value]
    found: set[str] = set()
    for item in vals:
        if isinstance(item, Mapping):
            item = item.get("emailAddress", item)
            if isinstance(item, Mapping): item = item.get("address") or item.get("email") or item.get("name")
        for _, addr in getaddresses([str(item)]):
            if EMAIL_RE.fullmatch(addr.strip()): found.add(addr.strip().casefold())
        if EMAIL_RE.fullmatch(str(item).strip()): found.add(str(item).strip().casefold())
    return tuple(sorted(found))


def _list_strings(value: Any) -> tuple[str, ...]:
    if value is None: return ()
    vals = value if isinstance(value, (list, tuple, set)) else [value]
    out = set()
    for x in vals:
        x = _clean_scalar(x)
        if isinstance(x, str): out.add(x.strip())
        elif isinstance(x, (int, float)) and not isinstance(x, bool): out.add(str(x))
    return tuple(sorted(out, key=str.casefold))


def _datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime): dt = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        try: dt = datetime.fromtimestamp(value, tz=timezone.utc)
        except (ValueError, OverflowError, OSError): return None
    elif isinstance(value, str):
        try: dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError: return None
    else: return None
    if dt.tzinfo is None: return dt
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def _source_locator(event: Mapping[str, Any], raw_path: str | None) -> str | None:
    aid = event.get("artifact_ref") or event.get("evidence_id") or event.get("event_id")
    if aid and raw_path: return f"{aid}#{raw_path}"
    return str(aid) if aid else raw_path


def resolve_field(event: Mapping[str, Any], field_name: str, *, source_clock: SourceClock | None = None,
                  evidence_context: Mapping[str, Mapping[str, Any]] | None = None) -> ResolvedField:
    """Resolve a closed-vocabulary field. Invalid values are never coerced into matches."""
    raw = _mapping(event.get("raw")); source = str(event.get("source") or "").lower()
    value: Any = None; locator: str | None = None; invalid = False
    if field_name == "actor.normalized":
        v, locator = _get(event, "actor", "raw.sender", "raw.from")
        v = _clean_scalar(v)
        value = normalize_actor(str(v)) if v is not None else None
    elif field_name == "actor.email":
        v, locator = _get(event, "actor", "raw.sender", "raw.from")
        emails = _emails(v); value = emails[0] if emails else None
    elif field_name == "actor.username":
        v, locator = _get(event, "actor", "raw.username", "raw.user", "raw.account")
        v = _clean_scalar(v)
        if v is not None:
            s = str(v).strip()
            # Display-name email forms resolve to the local-part; IP literals
            # are network identifiers, never usernames.
            parsed_emails = _emails(s)
            if parsed_emails: s = parsed_emails[0].split("@", 1)[0]
            elif IP_RE.fullmatch(s) and normalize_ip(s.strip("[]")): s = None
            value = normalize_actor(s) if s else None
    elif field_name == "account.id":
        v, locator = _get(event, "account_id", "raw.account_id", "raw.account.id", "raw.user_id", "raw.mailbox_id")
        value = normalize_actor(str(_clean_scalar(v))) if _clean_scalar(v) is not None else None
    elif field_name == "recipients.emails":
        collected=[]
        for path in ("raw.recipients", "raw.to", "raw.cc", "raw.bcc"):
            v, loc = _get(event, path)
            if v is not None:
                collected.extend(_emails(v)); locator = loc
        value = tuple(sorted(set(collected))) or None
    elif field_name == "device.id":
        v, locator = _get(event, "device", "raw.device_id", "raw.device", "raw.hostname", "raw.host")
        value = normalize_device(str(_clean_scalar(v))) if _clean_scalar(v) is not None else None
    elif field_name == "message.id":
        v, locator = _get(event, "message_id", "raw.internetMessageId", "raw.raw_headers.message-id", "raw.headers.message-id")
        if v is None and source in ("gmail", "outlook"):
            v, locator = _get(event, "raw.id")
        value = str(_clean_scalar(v)).strip().strip("<>").casefold() if _clean_scalar(v) is not None else None
    elif field_name == "message.references":
        v, locator = _get(event, "raw.raw_headers.references", "raw.raw_headers.in-reply-to", "raw.references", "raw.inReplyTo", "raw.in_reply_to")
        value = tuple(sorted({x.strip("<> ").casefold() for x in re.findall(r"<[^>]+>|[^\s]+", str(v or "")) if _clean_scalar(x)})) or None
    elif field_name == "thread.id":
        v, locator = _get(event, "thread_id", "raw.threadId", "raw.conversationId", "raw.conversation_id")
        value = str(_clean_scalar(v)).strip() if _clean_scalar(v) is not None else None
    elif field_name in ("attachment.sha256", "attachment.names"):
        v, locator = _get(event, "raw.attachments")
        vals = []
        if isinstance(v, list):
            for a in v:
                if not isinstance(a, Mapping): continue
                if field_name.endswith("sha256"):
                    h = a.get("sha256") or a.get("content_hash")
                    if isinstance(h, str) and re.fullmatch(r"[0-9a-fA-F]{64}", h.strip()): vals.append(h.lower())
                else:
                    n = _clean_scalar(a.get("filename") or a.get("name"))
                    if n: vals.append(normalize_file_object(str(n)))
        value = tuple(sorted(set(x for x in vals if x))) or None
    elif field_name == "file.sha256":
        h = event.get("content_sha256") or extract_content_hash(event)
        locator = "object/raw.content_hash|file_sha256|sha256"
        value = h.lower() if isinstance(h, str) and re.fullmatch(r"[0-9a-fA-F]{64}", h) else None
    elif field_name == "file.name":
        v, locator = _get(event, "object", "raw.filename", "raw.file_name", "raw.name")
        value = normalize_file_object(str(v), action=event.get("action")) if _clean_scalar(v) is not None else None
    elif field_name == "file.mime":
        v, locator = _get(event, "raw.mime_type", "raw.mimeType", "raw.content_type")
        if v is None:
            att, _ = _get(event, "raw.attachments")
            if isinstance(att, list) and att: v = att[0].get("mimeType") or att[0].get("contentType")
        value = _list_strings(v) or None
    elif field_name == "file.size":
        v, locator = _get(event, "raw.size", "raw.file_size")
        if v is None:
            att, _ = _get(event, "raw.attachments")
            if isinstance(att, list) and att: v = att[0].get("size")
        try: value = (float(v),) if v is not None and float(v) >= 0 else None
        except (ValueError, TypeError): invalid = True
    elif field_name in ("time.utc", "time.interval"):
        v, locator = _get(event, "timestamp", "raw.timestamp", "raw.time", "raw.ts")
        dt = _datetime(v)
        if v is not None and dt is None: invalid = True
        elif dt is not None:
            value = effective_interval(dt, source_clock) if field_name == "time.interval" else dt
    elif field_name == "time.quality":
        v, locator = _get(event, "timestamp_quality", "raw.timestamp_quality", "raw.time_quality")
        value = str(_clean_scalar(v)).lower() if _clean_scalar(v) is not None else None
    elif field_name == "time.tz_assumption":
        v, locator = _get(event, "tz_assumption", "raw.tz_assumption", "raw.timezone_assumption")
        if v is None:
            ts = event.get("timestamp")
            value = "explicit_offset" if isinstance(ts, str) and (ts.endswith("Z") or re.search(r"[+-]\d\d:\d\d$", ts)) else None
        else: value = str(v).lower()
    elif field_name == "time.clock_uncertainty_seconds":
        value = source_clock.uncertainty.total_seconds() if source_clock else 0.0; locator = "source_clock.uncertainty"
    elif field_name in ("net.ip", "net.src_ip", "net.dst_ip"):
        paths = {"net.ip": ("raw.src_ip", "raw.dst_ip", "raw.id.orig_h", "raw.id.resp_h", "ip"),
                 "net.src_ip": ("raw.src_ip", "raw.id.orig_h"), "net.dst_ip": ("raw.dst_ip", "raw.id.resp_h")}[field_name]
        if field_name == "net.ip":
            vals = [normalize_ip(str(x)) for path in paths for x, _ in [_get(event, path)] if x]
            value = tuple(sorted(set(x for x in vals if x))) or None
            locator = "raw network endpoint fields"
        else:
            v, locator = _get(event, *paths)
            value = normalize_ip(str(v)) if v is not None else None
            if v is not None and value is None: invalid = True
    elif field_name in ("net.src_port", "net.dst_port"):
        suffix = "sport" if field_name.endswith("src_port") else "dport"
        v, locator = _get(event, f"raw.tcp_{suffix}", f"raw.udp_{suffix}", f"raw.id.orig_p" if suffix == "sport" else "raw.id.resp_p")
        try: value = int(v) if v is not None and 0 <= int(v) <= 65535 else None
        except (ValueError, TypeError): invalid = True
    elif field_name == "net.protocol":
        v, locator = _get(event, "raw.protocol", "raw.proto")
        value = str(_clean_scalar(v)).upper() if _clean_scalar(v) is not None else None
    elif field_name in ("net.domain", "net.dns_answers"):
        if field_name == "net.domain":
            paths = ("raw.dns_query", "raw.query", "raw.domain", "raw.host", "raw.url")
        else: paths = ("raw.dns_answers", "raw.answers")
        v, locator = _get(event, *paths)
        vals = _list_strings(v)
        if field_name == "net.domain":
            domains=[]
            for x in vals:
                host = urlparse(x if "://" in x else "//"+x).hostname or x
                domains.append(host.rstrip(".").casefold())
            value = tuple(sorted(set(domains))) or None
        else: value = tuple(sorted(set(vals))) or None
    elif field_name == "net.session_id":
        v, locator = _get(event, "net_session_id", "raw.uid", "raw.session_id", "raw.connection_id")
        value = str(_clean_scalar(v)) if _clean_scalar(v) is not None else None
    elif field_name == "net.capture_id":
        v, locator = _get(event, "capture_id", "raw.capture_id")
        value = str(_clean_scalar(v)) if _clean_scalar(v) is not None else None
    elif field_name == "net.user_agent":
        v, locator = _get(event, "raw.user_agent", "raw.user-agent")
        value = str(_clean_scalar(v)) if _clean_scalar(v) is not None else None
    elif field_name in ("content.subject", "content.body", "content.text"):
        paths = {"content.subject": ("raw.subject",), "content.body": ("raw.body.content", "raw.body", "raw.text_body"),
                 "content.text": ("object", "raw.text", "raw.message", "raw.body.content", "raw.body")}[field_name]
        v, locator = _get(event, *paths)
        if isinstance(v, Mapping): v = v.get("content")
        value = str(_clean_scalar(v)) if _clean_scalar(v) is not None else None
    elif field_name == "content.url_domains":
        v, locator = _get(event, "object", "raw.url", "raw.urls")
        vals = _list_strings(v); domains=[]
        for x in vals:
            host = urlparse(x if "://" in x else "//"+x).hostname
            if host: domains.append(host.casefold().rstrip("."))
        value = tuple(sorted(set(domains))) or None
    elif field_name == "event.action":
        v, locator = _get(event, "action")
        value = str(_clean_scalar(v)).lower() if _clean_scalar(v) is not None else None
    elif field_name in ("event.source", "prov.source"):
        v, locator = _get(event, "source")
        value = str(v).lower() if v else None
    elif field_name == "prov.parser_confidence":
        v, locator = _get(event, "parser_confidence", "extraction_quality", "raw.parser_confidence", "raw.extraction_quality")
        try:
            value = float(v) if v is not None and 0 <= float(v) <= 1 else None
            if v is not None and value is None: invalid = True
        except (ValueError, TypeError): invalid = True
    elif field_name == "prov.acquisition_method":
        v, locator = _get(event, "acquisition_method", "raw.acquisition_method")
        value = str(_clean_scalar(v)).lower() if _clean_scalar(v) is not None else None
    elif field_name == "prov.integrity":
        v, locator = _get(event, "integrity_status")
        if v is None:
            ctx = _mapping(evidence_context).get(str(event.get("evidence_id") or ""), {})
            status, verify = ctx.get("status"), ctx.get("verify_state")
            if status in ("QUARANTINED", "REMOVED"): v = status
            elif verify: v = verify
            elif status == "ACTIVE": v = "UNVERIFIED"
            else: v = None
            locator = "evidence_context"
        value = str(v).upper() if v else None
    elif field_name == "prov.evidence_id":
        v, locator = _get(event, "evidence_id")
        value = str(v) if v else None
    else:
        raise KeyError(f"unsupported correlation field {field_name!r}")
    status = "INVALID" if invalid else ("PRESENT" if value is not None and value != () else "MISSING")
    return ResolvedField(field_name, value, status, _source_locator(event, locator))


def resolve_event(event: Mapping[str, Any], *, source_clock: SourceClock | None = None,
                  evidence_context: Mapping[str, Mapping[str, Any]] | None = None) -> dict[str, ResolvedField]:
    from .vocabulary import FIELD_NAMES
    return {name: resolve_field(event, name, source_clock=source_clock, evidence_context=evidence_context) for name in sorted(FIELD_NAMES)}
