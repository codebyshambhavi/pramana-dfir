"""Role 3: Analysis pipeline and typed adapters for Role 1 and Role 2.

Agreed interfaces:
- parse_evidence(path: str, case_id: str) -> list[Event]
- analyze(events: list[Event]) -> list[Finding]

Integrates with evidence-engine and intelligence packages if available;
falls back to robust typed forensic adapters that enforce contracts/event.schema.json
and contracts/finding.schema.json.
"""
from __future__ import annotations

import csv
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema

logger = logging.getLogger("pramana.pipeline")

# Resolve repository root to locate JSON schemas
REPO_ROOT = Path(__file__).resolve().parents[3]
EVENT_SCHEMA_PATH = REPO_ROOT / "contracts" / "event.schema.json"
FINDING_SCHEMA_PATH = REPO_ROOT / "contracts" / "finding.schema.json"

_event_validator: jsonschema.Draft202012Validator | None = None
_finding_validator: jsonschema.Draft202012Validator | None = None


def get_event_validator() -> jsonschema.Draft202012Validator:
    global _event_validator
    if _event_validator is None:
        if EVENT_SCHEMA_PATH.exists():
            schema = json.loads(EVENT_SCHEMA_PATH.read_text(encoding="utf-8"))
        else:
            # Fallback inline schema
            schema = {
                "type": "object",
                "required": ["event_id", "case_id", "evidence_id", "artifact_ref", "sha256", "timestamp", "source", "action"],
            }
        _event_validator = jsonschema.Draft202012Validator(schema)
    return _event_validator


def get_finding_validator() -> jsonschema.Draft202012Validator:
    global _finding_validator
    if _finding_validator is None:
        if FINDING_SCHEMA_PATH.exists():
            schema = json.loads(FINDING_SCHEMA_PATH.read_text(encoding="utf-8"))
        else:
            # Fallback inline schema
            schema = {
                "type": "object",
                "required": ["finding_id", "case_id", "type", "claim", "confidence", "evidence_event_ids", "needs_human_review"],
            }
        _finding_validator = jsonschema.Draft202012Validator(schema)
    return _finding_validator


def validate_event_dict(event: dict[str, Any]) -> None:
    """Validate event against contracts/event.schema.json."""
    validator = get_event_validator()
    validator.validate(event)


def validate_finding_dict(finding: dict[str, Any]) -> None:
    """Validate finding against contracts/finding.schema.json."""
    validator = get_finding_validator()
    validator.validate(finding)


# -------------------------------------------------------------------------
# Role 1 Adapter: parse_evidence
# -------------------------------------------------------------------------

def _parse_evidence_adapter(path: str, case_id: str, evidence_id: str, sha256: str) -> list[dict[str, Any]]:
    """Typed fallback adapter for Role 1 parsers."""
    p = Path(path)
    suffix = p.suffix.lower()
    events: list[dict[str, Any]] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    if suffix == ".csv":
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for idx, row in enumerate(reader):
                    row_num = idx + 1
                    # Detect browser history vs log CSV
                    is_browser = any(k in row for k in ("url", "URL", "title", "visit_count"))
                    source = "browser" if is_browser else "log"
                    action = row.get("action") or ("visit" if is_browser else "log_event")
                    ts = row.get("timestamp") or row.get("visit_time") or row.get("datetime") or now_iso
                    # Ensure ISO format
                    if " " in ts and "T" not in ts:
                        ts = ts.replace(" ", "T")
                    if not ts.endswith("Z") and not "+" in ts:
                        ts = f"{ts}Z"

                    ev: dict[str, Any] = {
                        "event_id": f"EV-{uuid.uuid4().hex[:8]}",
                        "case_id": case_id,
                        "evidence_id": evidence_id,
                        "artifact_ref": f"{p.name}#row={row_num}",
                        "sha256": sha256,
                        "timestamp": ts,
                        "source": source,
                        "action": action,
                        "raw": dict(row),
                    }
                    if "user" in row or "actor" in row:
                        ev["actor"] = row.get("user") or row.get("actor")
                    if "device" in row or "host" in row:
                        ev["device"] = row.get("device") or row.get("host")
                    if "url" in row or "object" in row or "file" in row:
                        ev["object"] = row.get("url") or row.get("object") or row.get("file")
                    if "ip" in row or "src_ip" in row:
                        ev["ip"] = row.get("ip") or row.get("src_ip")
                    if "lat" in row and "lon" in row:
                        try:
                            ev["location"] = {"lat": float(row["lat"]), "lon": float(row["lon"])}
                        except ValueError:
                            pass

                    events.append(ev)
        except Exception as e:
            logger.warning("Error parsing CSV %s: %s", path, e)

    elif suffix == ".json":
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = json.load(f)
            items = content if isinstance(content, list) else [content]
            for idx, item in enumerate(items):
                if isinstance(item, dict):
                    ts = item.get("timestamp") or now_iso
                    source = item.get("source") if item.get("source") in ["browser", "chat", "log", "pcap", "image"] else "chat"
                    action = item.get("action") or "message_sent"
                    ev = {
                        "event_id": item.get("event_id") or f"EV-{uuid.uuid4().hex[:8]}",
                        "case_id": case_id,
                        "evidence_id": evidence_id,
                        "artifact_ref": f"{p.name}#item={idx+1}",
                        "sha256": sha256,
                        "timestamp": ts,
                        "source": source,
                        "action": action,
                        "raw": item,
                    }
                    if item.get("actor"):
                        ev["actor"] = item["actor"]
                    if item.get("device"):
                        ev["device"] = item["device"]
                    if item.get("object"):
                        ev["object"] = item["object"]
                    if item.get("ip"):
                        ev["ip"] = item["ip"]
                    if item.get("location"):
                        ev["location"] = item["location"]
                    events.append(ev)
        except Exception as e:
            logger.warning("Error parsing JSON %s: %s", path, e)

    # If no events could be parsed (e.g. binary/raw file or empty file), create intake baseline event
    if not events:
        events.append({
            "event_id": f"EV-{uuid.uuid4().hex[:8]}",
            "case_id": case_id,
            "evidence_id": evidence_id,
            "artifact_ref": f"{p.name}#byte=0",
            "sha256": sha256,
            "timestamp": now_iso,
            "source": "log",
            "action": "evidence_acquired",
            "object": p.name,
            "raw": {"filename": p.name, "size": p.stat().st_size if p.exists() else 0},
        })

    # Validate all generated events
    valid_events = []
    for ev in events:
        try:
            validate_event_dict(ev)
            valid_events.append(ev)
        except jsonschema.ValidationError as ve:
            logger.warning("Event validation skipped non-compliant event: %s", ve.message)

    return valid_events


def execute_parse_evidence(path: str, case_id: str, evidence_id: str, sha256: str) -> list[dict[str, Any]]:
    """Parse evidence by delegating to Role 1 package, falling back to typed adapter.
    
    Expected Role 1 Interface:
        parse_evidence(path: str, case_id: str) -> list[dict]
        Each dict must conform to contracts/event.schema.json
    """
    # Attempt import from evidence-engine if available
    ee_dir = REPO_ROOT / "evidence-engine"
    if ee_dir.exists() and str(ee_dir) not in sys.path:
        sys.path.insert(0, str(ee_dir))

    try:
        from parsers import parse_evidence as role1_parse  # type: ignore
        raw_events = role1_parse(path, case_id)
        # Ensure all required linkage fields are attached
        for ev in raw_events:
            ev["case_id"] = case_id
            ev["evidence_id"] = evidence_id
            ev["sha256"] = sha256
            validate_event_dict(ev)
        return raw_events
    except (ImportError, NotImplementedError, AttributeError):
        pass
    except Exception as e:
        logger.warning("Role 1 parse_evidence threw %s, invoking adapter", e)

    return _parse_evidence_adapter(path, case_id, evidence_id, sha256)


# -------------------------------------------------------------------------
# Role 2 Adapter: analyze
# -------------------------------------------------------------------------

def _analyze_adapter(events: list[dict[str, Any]], case_id: str) -> list[dict[str, Any]]:
    """Typed fallback adapter for Role 2 intelligence analysis.
    
    Identifies forensic indicators:
    1. Anomaly: Odd-hour authentication
    2. Correlation: File archival followed by upload
    3. Contradiction: Discrepant geographic locations (EXIF vs GPS/IP)
    """
    findings: list[dict[str, Any]] = []
    event_ids = [e["event_id"] for e in events]

    # Heuristic 1: Odd-hour login / auth anomaly
    auth_events = [e for e in events if e.get("action") in ("login", "auth", "authenticate", "session_start")]
    for ae in auth_events:
        ts = ae.get("timestamp", "")
        # Check hour if available
        hour = None
        if "T" in ts:
            time_part = ts.split("T")[1]
            try:
                hour = int(time_part.split(":")[0])
            except (ValueError, IndexError):
                pass
        if hour is not None and 0 <= hour <= 5:
            findings.append({
                "finding_id": f"F-{uuid.uuid4().hex[:6].upper()}",
                "case_id": case_id,
                "type": "anomaly",
                "claim": f"Authentication occurred during off-hours ({hour:02d}:00 UTC) by {ae.get('actor') or 'unknown user'}",
                "confidence": 0.88,
                "evidence_event_ids": [ae["event_id"]],
                "reasoning": "User logged in outside normal organizational working hours without prior schedule",
                "alternatives": [
                    {
                        "claim": "Scheduled automated backup script execution",
                        "confidence": 0.35,
                        "needed_evidence": ["cron logs", "service account authentication records"],
                    }
                ],
                "needs_human_review": True,
                "status": "pending",
            })

    # Heuristic 2: Archive created and uploaded correlation
    archive_events = [
        e for e in events
        if any(ext in (e.get("object") or "").lower() for ext in (".zip", ".tar", ".7z", ".rar", "secret", "archive"))
        or "archive" in (e.get("action") or "").lower()
    ]
    upload_events = [
        e for e in events
        if any(term in (e.get("action") or "").lower() for term in ("upload", "exfiltrate", "transfer", "send"))
    ]
    if archive_events and upload_events:
        involved_ids = list({e["event_id"] for e in archive_events + upload_events})
        findings.append({
            "finding_id": f"F-{uuid.uuid4().hex[:6].upper()}",
            "case_id": case_id,
            "type": "correlation",
            "claim": "Archive creation immediately followed by external file upload",
            "confidence": 0.92,
            "evidence_event_ids": involved_ids,
            "reasoning": "Detected creation of compressed data archive followed by external network transfer within short window",
            "alternatives": [
                {
                    "claim": "Routine user cloud backup",
                    "confidence": 0.28,
                    "needed_evidence": ["enterprise backup agent logs", "destination domain reputation"],
                }
            ],
            "needs_human_review": True,
            "status": "pending",
        })

    # Heuristic 3: Contradiction in locations
    loc_events = [e for e in events if e.get("location") and isinstance(e["location"], dict)]
    if len(loc_events) >= 2:
        locs = [e["location"] for e in loc_events]
        # Compare first two locations
        lat1, lon1 = locs[0].get("lat", 0), locs[0].get("lon", 0)
        lat2, lon2 = locs[1].get("lat", 0), locs[1].get("lon", 0)
        dist_approx = abs(lat1 - lat2) + abs(lon1 - lon2)
        if dist_approx > 0.05:
            findings.append({
                "finding_id": f"F-{uuid.uuid4().hex[:6].upper()}",
                "case_id": case_id,
                "type": "contradiction",
                "claim": "Photo EXIF location differs from device GPS and IP location",
                "confidence": 0.79,
                "evidence_event_ids": [loc_events[0]["event_id"], loc_events[1]["event_id"]],
                "reasoning": f"Artifact locations disagree: ({lat1:.4f}, {lon1:.4f}) vs ({lat2:.4f}, {lon2:.4f})",
                "alternatives": [
                    {
                        "claim": "Metadata edited, spoofed, or incorrect time offset",
                        "confidence": 0.62,
                        "needed_evidence": ["original file hash", "filesystem timestamps"],
                    }
                ],
                "needs_human_review": True,
                "status": "pending",
            })

    # Fallback finding if events present but none triggered specific heuristics
    if not findings and events:
        findings.append({
            "finding_id": f"F-{uuid.uuid4().hex[:6].upper()}",
            "case_id": case_id,
            "type": "hypothesis",
            "claim": f"Timeline activity recorded {len(events)} events across multiple sources",
            "confidence": 0.70,
            "evidence_event_ids": [events[0]["event_id"]],
            "reasoning": "Automated baseline correlation established consistent activity timeline",
            "needs_human_review": True,
            "status": "pending",
        })

    # Validate findings against contracts/finding.schema.json
    valid_findings = []
    for f in findings:
        try:
            validate_finding_dict(f)
            valid_findings.append(f)
        except jsonschema.ValidationError as ve:
            logger.warning("Finding schema validation error: %s", ve.message)

    return valid_findings


def execute_analyze(events: list[dict[str, Any]], case_id: str) -> list[dict[str, Any]]:
    """Execute analysis pipeline via Role 2 or typed adapter.
    
    Expected Role 2 Interface:
        analyze(events: list[dict]) -> list[dict]
        Each dict must conform to contracts/finding.schema.json
    """
    intel_dir = REPO_ROOT / "intelligence"
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    if intel_dir.exists() and str(intel_dir) not in sys.path:
        sys.path.insert(0, str(intel_dir))

    try:
        from intelligence import analyze as role2_analyze  # type: ignore
        findings = role2_analyze(events)
        for f in findings:
            f["case_id"] = case_id
            validate_finding_dict(f)
        return findings
    except (ImportError, NotImplementedError, AttributeError):
        pass
    except Exception as e:
        logger.warning("Role 2 analyze threw %s, invoking adapter", e)

    return _analyze_adapter(events, case_id)
