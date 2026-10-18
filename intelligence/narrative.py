"""Role 2: local LLM (Ollama) timeline that cites only the events it is given."""


def write_narrative(events: list[dict]) -> str:
    """Reject any sentence that cites an event ID not in the input or cites none.

    TODO (Role 2): implement.
    """
    raise NotImplementedError("write_narrative")
