"""Role 1: append-only, hash-chained chain-of-custody log."""
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional


def _hash_line(line: str) -> str:
    """Return the SHA-256 hash of a line as a hex string."""
    return hashlib.sha256(line.encode('utf-8')).hexdigest()


def _deterministic_json_dump(obj: Dict[str, Any]) -> str:
    """Return a deterministic JSON string representation of the object."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))


def append_entry(log_path: str, actor: str, action: str, evidence_id: str, sha256: str) -> Dict[str, Any]:
    """Append one JSON line (who, what, when, file hash, previous line's hash).

    Args:
        log_path: Path to the custody log file
        actor: Who performed the action
        action: What action was performed
        evidence_id: Evidence identifier (EVID-XXX format)
        sha256: SHA-256 hash of the evidence file

    Returns:
        The appended entry as a dictionary
    """
    # Read the last line to get previous hash
    previous_hash = "0" * 64  # Deterministic empty hash (64 zeros)

    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            if lines:
                last_line = lines[-1].rstrip("\r\n")
                if not last_line:
                    raise ValueError("Custody log contains a blank trailing line")
                previous_hash = _hash_line(last_line)
    except FileNotFoundError:
        # File doesn't exist yet, which is fine - we'll create it
        pass

    # Create the entry
    entry = {
        "actor": actor,
        "action": action,
        "evidence_id": evidence_id,
        "sha256": sha256,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "previous_hash": previous_hash
    }

    # Deterministic JSON serialization
    entry_json = _deterministic_json_dump(entry)

    # Append to the log file
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(entry_json + '\n')

    return entry


def verify_log(log_path: str) -> bool:
    """Return True only if no earlier line was edited.

    Args:
        log_path: Path to the custody log file

    Returns:
        True if the log is valid (no tampering), False otherwise
    """
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        # Empty/nonexistent log is considered valid
        return True

    if not lines:
        # Empty log is valid
        return True

    # Verify each line
    previous_hash = "0" * 64  # Starting hash for first entry

    for line_num, line in enumerate(lines, 1):
        line = line.rstrip("\r\n")
        if not line:
            # Blank lines would break the append-only chain and are invalid.
            return False

        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            # Malformed JSON
            return False

        # Check that the entry has all required fields
        required_fields = ["actor", "action", "evidence_id", "sha256", "timestamp", "previous_hash"]
        if not all(field in entry for field in required_fields):
            return False

        # The line itself is part of the chain. Require canonical serialization
        # so whitespace/key-order edits are detected even on the final entry.
        if _deterministic_json_dump(entry) != line:
            return False

        # Verify the previous_hash matches
        if entry["previous_hash"] != previous_hash:
            return False

        # Recompute the hash of this line for the next iteration
        # We need to hash the exact line as it appears in the file
        previous_hash = _hash_line(line)

    return True