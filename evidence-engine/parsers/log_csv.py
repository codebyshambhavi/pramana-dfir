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
- family = "system_log" by default; scheduler/authentication filenames retain
  their more specific Event v1.1 family
- artifact_ref = "{filename}#row={row_number}" (1-indexed)
- object = object column value (when present)
- raw = original row as dict
"""
import csv
from pathlib import Path
from typing import Dict, List, Any

from parsers.provenance import provenance_fields
from parsers.timestamps import normalize_timestamp_with_basis
from parsers.vocabulary import canonical_action

PARSER_NAME = "log_csv"
PARSER_VERSION = "1.1.0"
FAMILY = "system_log"


def _family_for_path(path: str) -> str:
    """Keep known log-like evidence families distinct without changing source."""
    stem = Path(path).stem.casefold()
    if "scheduler" in stem:
        return "scheduler"
    if "authentication" in stem or "auth" in stem or "vpn" in stem:
        return "authentication"
    return FAMILY


def parse(path: str, case_id: str, evidence_id: str, sha256: str) -> List[Dict[str, Any]]:
    """Parse log-like CSV evidence and return Events.

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

                timestamp, tz_basis = normalize_timestamp_with_basis(row['timestamp'])

                # Build the event
                event = {
                    "event_id": f"EV-{row_idx:06d}",  # Simple sequential ID
                    "case_id": case_id,
                    "evidence_id": evidence_id,
                    "artifact_ref": artifact_ref,
                    "sha256": sha256,
                    "timestamp": timestamp,
                    "source": "log",
                    "action": canonical_action(row['action']),  # original kept in raw
                    "object": obj,
                    "raw": raw,
                    **provenance_fields(
                        parser=PARSER_NAME, version=PARSER_VERSION,
                        family=_family_for_path(path), tz_assumption=tz_basis,
                    ),
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