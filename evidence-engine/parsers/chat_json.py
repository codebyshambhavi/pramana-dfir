"""Role 1: parser for chat export (JSON).

Simple synthetic JSON array format:
[
  {
    "timestamp": "ISO 8601 timestamp",
    "action": "action performed",
    "actor": "user (optional)",
    "device": "device used (optional)",
    "object": "object of action (optional)",
    "ip": "IP address (optional)",
    "device_gps": {"lat": 0.0, "lon": 0.0}   (optional, device-reported GPS)
  }
]

Each item becomes one Event with:
- source = "chat"
- artifact_ref = "{filename}#item={index}" (0-indexed for array position)
- location = item["device_gps"] as {"lat", "lon"} when present (the device's own
  GPS fix). "ip_location" is IP-derived geolocation, a different thing, and is
  left in raw only.
- raw = original JSON object
"""
import json
from typing import Dict, List, Any

from parsers.provenance import provenance_fields
from parsers.timestamps import normalize_timestamp_with_basis
from parsers.vocabulary import canonical_action

PARSER_NAME = "chat_json"
PARSER_VERSION = "1.1.0"
FAMILY = "chat_export"


def _device_gps(item: Dict[str, Any], item_idx: int):
    """Return {"lat", "lon"} from item["device_gps"], None if absent.

    A present-but-malformed value raises instead of being dropped, so a
    corrupted GPS fix can never silently disappear from the Event.
    """
    gps = item.get("device_gps")
    if gps is None:
        return None
    if not isinstance(gps, dict):
        raise ValueError(f"Item {item_idx}: 'device_gps' must be an object with lat and lon")
    lat, lon = gps.get("lat"), gps.get("lon")
    for name, value, bound in (("lat", lat, 90.0), ("lon", lon, 180.0)):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"Item {item_idx}: 'device_gps.{name}' must be a number")
        if not -bound <= float(value) <= bound:
            raise ValueError(f"Item {item_idx}: 'device_gps.{name}' out of range: {value}")
    return {"lat": float(lat), "lon": float(lon)}


def parse(path: str, case_id: str, evidence_id: str, sha256: str) -> List[Dict[str, Any]]:
    """Parse chat JSON and return Events.

    Args:
        path: Path to the JSON file
        case_id: Case identifier
        evidence_id: Evidence identifier
        sha256: SHA-256 hash of the source file

    Returns:
        List of Event dictionaries conforming to contracts/event.schema.json

    Raises:
        ValueError: For malformed JSON or missing required fields
    """
    with open(path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")

    # Expecting an array/object at the root
    if not isinstance(data, list):
        raise ValueError("Expected JSON array at root")

    events = []

    for item_idx, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"Item {item_idx}: expected JSON object")

        try:
            # Validate required fields
            if 'timestamp' not in item or not item['timestamp']:
                raise ValueError(f"Item {item_idx}: missing or empty 'timestamp'")
            if 'action' not in item or not item['action']:
                raise ValueError(f"Item {item_idx}: missing or empty 'action'")

            # Build artifact_ref (0-indexed for accurate array position)
            filename = path.split('/')[-1].split('\\')[-1]  # Get filename from path
            artifact_ref = f"{filename}#item={item_idx}"

            timestamp, tz_basis = normalize_timestamp_with_basis(item['timestamp'])

            # Build the event (1-indexed event ID for human readability, like other parsers)
            event = {
                "event_id": f"EV-{item_idx + 1:06d}",  # 1-indexed sequential ID
                "case_id": case_id,
                "evidence_id": evidence_id,
                "artifact_ref": artifact_ref,
                "sha256": sha256,
                "timestamp": timestamp,
                "source": "chat",
                "action": canonical_action(item['action']),  # original kept in raw
                "raw": item,  # Preserve original object
                **provenance_fields(
                    parser=PARSER_NAME, version=PARSER_VERSION,
                    family=FAMILY, tz_assumption=tz_basis,
                ),
            }

            # Add optional fields if present and not empty/null
            if 'actor' in item and item['actor'] is not None and item['actor'] != '':
                event["actor"] = item['actor']
            if 'device' in item and item['device'] is not None and item['device'] != '':
                event["device"] = item['device']
            if 'object' in item and item['object'] is not None and item['object'] != '':
                event["object"] = item['object']
            if 'ip' in item and item['ip'] is not None and item['ip'] != '':
                event["ip"] = item['ip']
            location = _device_gps(item, item_idx)
            if location is not None:
                event["location"] = location

            events.append(event)

        except KeyError as e:
            raise ValueError(f"Item {item_idx}: missing required field {e}")

    return events