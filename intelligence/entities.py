"""Role 3 / T5: Entity normalization and canonical key generation.

Provides deterministic normalization functions for:
- Actor (case-folded, whitespace-stripped, preserving original values for display)
- Device (whitespace-normalized, case-folded, safe missing-value handling)
- IP (strict standard ipaddress parsing, compressed format, invalid values rejected)
- File/object (basename extraction from paths and URLs, case-normalization, content hashes)

No separate database table is required; canonical keys are computed on demand
and used by candidate generation and link promotion.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import unquote, urlparse

_HEX_HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_PERCEPTUAL_HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{16}$")
_SHORT_HEX_IDENTIFIER_PATTERN = re.compile(r"^[0-9a-fA-F]{1,31}$")
_MULTI_WS = re.compile(r"\s+")
_PLACEHOLDER_IDENTIFIERS = frozenset({"unknown", "none", "null", "n/a"})


def normalize_actor(raw: str | None) -> str | None:
    """Normalize actor identifier.

    - Strips leading/trailing whitespace
    - Case-folds for deterministic matching
    - Preserves non-empty string or returns None
    - Never performs fuzzy merging of uncertain aliases
    """
    if raw is None:
        return None
    val = _MULTI_WS.sub(" ", raw.strip())
    if not val:
        return None
    return val.lower()


def normalize_device(raw: str | None) -> str | None:
    """Normalize device identifier.

    - Handles missing values safely (None or whitespace-only returns None)
    - Normalizes internal whitespace to single spaces
    - Case-folds for consistent cross-source device matching
    """
    if raw is None:
        return None
    val = _MULTI_WS.sub(" ", raw.strip())
    if not val:
        return None
    return val.lower()


def normalize_ip(raw: str | None) -> str | None:
    """Normalize IP address using standard Python ipaddress library.

    - Strips leading/trailing whitespace
    - Validates IPv4 and IPv6 format strictly
    - Returns canonical compressed representation (e.g. '203.0.113.42')
    - Invalid values return None and will NOT generate matches
    """
    if raw is None:
        return None
    val = raw.strip()
    if not val:
        return None
    try:
        addr = ipaddress.ip_address(val)
        return addr.compressed.lower()
    except ValueError:
        return None


def normalize_file_object(raw: str | None, action: str | None = None) -> str | None:
    """Normalize file or object identifier to a canonical key.

    Rules:
    - If empty or None -> None
    - If a content hash (32, 40, or 64 hex characters) -> return lowercase hex
    - If a URL (http/https/ftp):
      - For file upload/transfer actions ('file_upload', 'upload', 'file_download', 'download')
        -> extract unquoted basename of the URL path.
      - If no file path exists (e.g. root domain only) -> return None.
      - For general non-upload URL actions (e.g. 'visit', 'browse') -> return the full URL
        normalized, so it does not match unrelated file archives.
    - If a filesystem path (Windows or POSIX) -> extract the basename
    - Normalize case (lowercase) for case-insensitive filesystem compatibility
    """
    if raw is None:
        return None
    val = raw.strip()
    if not val:
        return None

    # A complete cryptographic digest is an exact file identifier.  Short
    # hexadecimal values are neither cryptographic content hashes nor safe
    # object keys: notably, a 16-character value has perceptual-hash shape.
    if _HEX_HASH_PATTERN.fullmatch(val):
        return val.lower()
    if (
        val.lower() in _PLACEHOLDER_IDENTIFIERS
        or _PERCEPTUAL_HASH_PATTERN.fullmatch(val)
        or _SHORT_HEX_IDENTIFIER_PATTERN.fullmatch(val)
    ):
        return None

    # Check if a prose string contains a referenced filename pattern (e.g. "Discussed CASE-001.tar.gz")
    file_match = re.search(
        r"[\w.-]+\.(?:tar\.gz|tar|zip|gz|7z|rar|csv|json|pdf|txt|log|docx|xlsx|py|sh|pcap|pcapng|jpg|jpeg|png)",
        val,
        re.IGNORECASE,
    )
    if file_match and len(val.split()) > 1:
        return file_match.group(0).lower()

    # Check for URL
    try:
        parsed = urlparse(val)
        if parsed.scheme in ("http", "https", "ftp") and parsed.netloc:
            act = (action or "").lower()
            if act in ("file_upload", "upload", "file_download", "download"):
                path = parsed.path.rstrip("/")
                if not path or path == "/":
                    return None
                basename = unquote(path.rsplit("/", 1)[-1])
                if not basename:
                    return None
                return basename.lower()
            else:
                # Unrelated URLs must not match file archives
                return val.lower()
    except Exception:
        pass

    # Normalize filesystem path (handle both Windows '\' and POSIX '/')
    clean_path = val.replace("\\", "/").rstrip("/")
    if not clean_path:
        return None
    basename = clean_path.rsplit("/", 1)[-1]
    if not basename:
        return None
    return basename.lower()


def extract_content_hash(event: Mapping[str, Any]) -> str | None:
    """Extract content hash from an event's object or raw metadata.

    Inspects:
    1. event.object (if 32-, 40-, or 64-character hex)
    2. event.raw.content_hash, event.raw.file_sha256, or event.raw.sha256
    Perceptual hashes are intentionally excluded: they describe visual similarity,
    not byte-identical file content or a shared file/object identifier. They must
    be handled by a dedicated image-similarity signal, never SAME_OBJECT_FLOW.
    Note: Does NOT return event.sha256 (the evidence source file hash).
    """
    obj = event.get("object")
    if isinstance(obj, str) and _HEX_HASH_PATTERN.match(obj.strip()):
        return obj.strip().lower()

    raw = event.get("raw")
    if isinstance(raw, dict):
        for key in ("content_hash", "file_sha256", "sha256"):
            val = raw.get(key)
            if isinstance(val, str) and val.strip():
                clean = val.strip().lower()
                if _HEX_HASH_PATTERN.fullmatch(clean):
                    return clean

    return None


@dataclass(frozen=True)
class CanonicalEntities:
    """Container for an event's normalized entities and original values."""

    actor: str | None
    device: str | None
    ip: str | None
    file_object: str | None
    content_hash: str | None
    raw_actor: str | None
    raw_device: str | None
    raw_ip: str | None
    raw_object: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "device": self.device,
            "ip": self.ip,
            "file_object": self.file_object,
            "content_hash": self.content_hash,
            "raw_actor": self.raw_actor,
            "raw_device": self.raw_device,
            "raw_ip": self.raw_ip,
            "raw_object": self.raw_object,
        }


def extract_canonical_entities(event: Mapping[str, Any]) -> CanonicalEntities:
    """Extract canonical entities and preserve raw representations."""
    raw_actor = event.get("actor")
    raw_device = event.get("device")
    raw_ip = event.get("ip")
    raw_object = event.get("object")
    action = event.get("action")

    return CanonicalEntities(
        actor=normalize_actor(raw_actor) if isinstance(raw_actor, str) else None,
        device=normalize_device(raw_device) if isinstance(raw_device, str) else None,
        ip=normalize_ip(raw_ip) if isinstance(raw_ip, str) else None,
        file_object=normalize_file_object(raw_object, action=action) if isinstance(raw_object, str) else None,
        content_hash=extract_content_hash(event),
        raw_actor=raw_actor if isinstance(raw_actor, str) else None,
        raw_device=raw_device if isinstance(raw_device, str) else None,
        raw_ip=raw_ip if isinstance(raw_ip, str) else None,
        raw_object=raw_object if isinstance(raw_object, str) else None,
    )
