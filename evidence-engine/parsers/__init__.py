"""Role 1 entry point used by the backend."""
from pathlib import Path


def parse_evidence(path: str, case_id: str) -> list[dict]:
    """Pick a parser by file type and return schema-valid Events.

    Unknown file types must raise ValueError with a clear message.
    TODO (Role 1): implement the dispatcher and call the parsers below.
    """
    suffix = Path(path).suffix.lower()
    raise NotImplementedError(f"parse_evidence for '{suffix}' files")
