"""Role 1: parser for chat export (JSON).

Simple synthetic JSON array format:
[
  {
    "timestamp": "ISO 8601 timestamp",
    "action": "action performed",
    "actor": "user (optional)",
    "device": "device used (optional)",
    "object": "object of action (optional)",
    "ip": "IP address (optional)"
  }
]

Each item becomes one Event with:
- source = "chat"
- artifact_ref = "{filename}#item={index}" (0-indexed for array position)
- raw = original JSON object
"""
import json
from typing import Dict, List, Any

from parsers.timestamps import normalize_timestamp


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

            # Build the event (1-indexed event ID for human readability, like other parsers)
            event = {
                "event_id": f"EV-{item_idx + 1:06d}",  # 1-indexed sequential ID
                "case_id": case_id,
                "evidence_id": evidence_id,
                "artifact_ref": artifact_ref,
                "sha256": sha256,
                "timestamp": normalize_timestamp(item['timestamp']),
                "source": "chat",
                "action": item['action'],
                "raw": item  # Preserve original object
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

            events.append(event)

        except KeyError as e:
            raise ValueError(f"Item {item_idx}: missing required field {e}")

    return events