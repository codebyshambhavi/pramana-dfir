"""Role 1: streaming SHA-256 and evidence IDs."""
import hashlib
from datetime import datetime, timezone
from pathlib import Path


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    """Return the hex SHA-256 of a file, read in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def intake_record(path: str, sequence: int) -> dict:
    """Return evidence ID, filename, size, SHA-256 and intake time for a file.

    TODO (Role 1): add acquisition fields the report needs (device, source).
    """
    file_path = Path(path)
    return {
        "evidence_id": f"EVID-{sequence:03d}",
        "filename": file_path.name,
        "size_bytes": file_path.stat().st_size,
        "sha256": sha256_file(path),
        "intake_time": datetime.now(timezone.utc).isoformat(),
    }
