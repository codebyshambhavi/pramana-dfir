"""Role 1: append-only, hash-chained chain-of-custody log."""


def append_entry(log_path: str, actor: str, action: str, evidence_id: str, sha256: str) -> dict:
    """Append one JSON line (who, what, when, file hash, previous line's hash).

    TODO (Role 1): implement. Each line must include the hash of the previous line.
    """
    raise NotImplementedError("custody.append_entry")


def verify_log(log_path: str) -> bool:
    """Return True only if no earlier line was edited.

    TODO (Role 1): implement.
    """
    raise NotImplementedError("custody.verify_log")
