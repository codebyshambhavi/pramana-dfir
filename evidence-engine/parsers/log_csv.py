"""Role 1: parser for system logs (CSV).

Supported synthetic CSV columns:
- timestamp (required): ISO 8601 timestamp
- action (required): action performed (e.g., 'login', 'file_access', 'process_start')
- actor (optional): user who performed the action
- device (optional): device where action occurred
- ip (optional): IP address
- object (optional): object of the action (e.g., filename, process name)

Each row becomes one Event with:
- source = "log"
- artifact_ref = "{filename}#row={row_number}" (1-indexed)
- object = object column value (when present)
- raw = original row as dict
"""
import csv
from typing import Dict, List, Any

from parsers.timestamps import normalize_timestamp


def parse(path: str, case_id: str, evidence_id: str, sha256: str) -> List[Dict[str, Any]]:
    """Parse system log CSV and return Events.

    Args:
        path: Path to the CSV file
        case_id: Case identifier
        evidence_id: Evidence identifier
        sha256: SHA-256 hash of the source file

    Returns:
        List of Event dictionaries conforming to contracts/event.schema.json

    Raises:
        ValueError: For malformed rows or missing required columns
    """
    events = []

    with open(path, 'r', encoding='utf-8') as f:
        # Try to detect dialect
        try:
            dialect = csv.Sniffer().sniff(f.read(1024))
            f.seek(0)
        except csv.Error:
            # Default to excel dialect
            f.seek(0)
            dialect = 'excel'

        reader = csv.DictReader(f, dialect=dialect)

        # Check required columns
        if not reader.fieldnames:
            raise ValueError("CSV file has no headers")

        required_columns = {'timestamp', 'action'}
        missing_columns = required_columns - set(reader.fieldnames)
        if missing_columns:
            raise ValueError(f"Missing required columns: {missing_columns}")

        # Process each row
        for row_idx, row in enumerate(reader, start=1):
            try:
                # Validate required fields are not empty
                if not row['timestamp'] or not row['action']:
                    raise ValueError(f"Row {row_idx}: missing required field value")

                # Build artifact_ref
                filename = path.split('/')[-1].split('\\')[-1]  # Get filename from path
                artifact_ref = f"{filename}#row={row_idx}"

                # Build object field (from object column if present)
                obj = row.get('object') if row.get('object') else None

                # Build raw field (preserve original row)
                raw = dict(row)

                # Build the event
                event = {
                    "event_id": f"EV-{row_idx:06d}",  # Simple sequential ID
                    "case_id": case_id,
                    "evidence_id": evidence_id,
                    "artifact_ref": artifact_ref,
                    "sha256": sha256,
                    "timestamp": normalize_timestamp(row['timestamp']),
                    "source": "log",
                    "action": row['action'],
                    "object": obj,
                    "raw": raw
                }

                # Add optional fields if present and not empty
                if row.get('actor'):
                    event["actor"] = row['actor']
                if row.get('device'):
                    event["device"] = row['device']
                if row.get('ip'):
                    event["ip"] = row['ip']

                events.append(event)

            except KeyError as e:
                raise ValueError(f"Row {row_idx}: missing column {e}")

    return events