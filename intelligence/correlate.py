"""Role 2: group events that share an actor, device, IP or file hash within a time window."""


def correlate(events: list[dict], window_seconds: int = 120) -> list[dict]:
    """Return correlation Findings (default window 120 seconds, configurable).

    TODO (Role 2): implement.
    """
    raise NotImplementedError("correlate")
