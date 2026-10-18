"""Role 1: parser for image metadata (ExifTool, perceptual hash)."""


def parse(path: str, case_id: str, evidence_id: str, sha256: str) -> list[dict]:
    """Return Events (see contracts/event.schema.json), one per row or packet.

    Every Event needs an artifact_ref that points back to the exact row or packet.
    TODO (Role 1): implement.
    """
    raise NotImplementedError("image_meta.parse")
