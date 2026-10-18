"""Role 2 entry point used by the backend."""


def analyze(events: list[dict]) -> list[dict]:
    """Run correlation, contradictions, anomalies, hypotheses and authenticity.

    Every returned Finding must validate against contracts/finding.schema.json
    and carry needs_human_review.
    TODO (Role 2): call the modules in this package and merge their findings.
    """
    raise NotImplementedError("intelligence.analyze")
