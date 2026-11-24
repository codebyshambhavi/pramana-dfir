"""Closed vocabularies shared by the correlation registry and its implementations.

The registry (``registry_v1.json``) is *data*. This module only lists the
building blocks the data may refer to, so a registry file that names an unknown
field, extraction method or normalisation kind is rejected at load time rather
than silently ignored at scoring time.

Nothing here is a weight, threshold or parameter list. Which parameters exist,
and how much they count, lives only in the registry file.
"""
from __future__ import annotations

# --- event sources -----------------------------------------------------------
# Matches the ``source`` enum of contracts/event.schema.json.
KNOWN_EVENT_SOURCES = ("browser", "chat", "log", "pcap", "image", "gmail", "outlook", "pst", "zeek")

# Source categories used to name the *kind* of pair a parameter applies to.
SOURCE_CATEGORY = {
    "gmail": "MAIL",
    "outlook": "MAIL",
    "pst": "MAIL",
    "chat": "CHAT",
    "browser": "WEB",
    "log": "LOG",
    "pcap": "NETWORK",
    "zeek": "NETWORK",
    "image": "IMAGE",
}
SOURCE_CATEGORIES = tuple(sorted(set(SOURCE_CATEGORY.values())))
UNKNOWN_CATEGORY = "OTHER"


def category_of(source: str | None) -> str:
    return SOURCE_CATEGORY.get((source or "").lower(), UNKNOWN_CATEGORY)


def pair_kind(source_a: str | None, source_b: str | None) -> str:
    """Order-independent pair kind, e.g. ``MAIL-NETWORK``."""
    a, b = sorted((category_of(source_a), category_of(source_b)))
    return f"{a}-{b}"


def all_pair_kinds() -> tuple[str, ...]:
    cats = sorted(set(SOURCE_CATEGORIES))
    return tuple(f"{cats[i]}-{cats[j]}" for i in range(len(cats)) for j in range(i, len(cats)))


def relation_type_matches(patterns: list[str] | tuple[str, ...], kind: str) -> bool:
    """``ANY`` matches everything; ``MAIL-*`` matches any pair containing MAIL."""
    left, right = kind.split("-", 1)
    for pattern in patterns:
        if pattern == "ANY" or pattern == kind:
            return True
        if pattern.endswith("-*") and pattern[:-2] in (left, right):
            return True
    return False


def valid_relation_pattern(pattern: str) -> bool:
    if pattern == "ANY":
        return True
    if pattern.endswith("-*"):
        return pattern[:-2] in SOURCE_CATEGORIES
    return pattern in all_pair_kinds()


# --- parameter classification ------------------------------------------------
ROLES = ("ANCHOR", "FEATURE", "CONTRADICTION", "RELIABILITY_FACTOR")
ROLE_TO_RELATIONSHIP_CLASS = {
    "ANCHOR": "PRIMARY",
    "FEATURE": "SECONDARY",
    "CONTRADICTION": "SECONDARY",
    "RELIABILITY_FACTOR": "SECONDARY",
}
RELATIONSHIP_CLASSES = ("PRIMARY", "SECONDARY")
FAMILIES = (
    "IDENTITY", "ARTIFACT", "TEMPORAL", "NETWORK", "CONTENT", "PROVENANCE", "CONTRADICTION",
)
DIRECTIONS = ("SUPPORTS", "WEAKENS")
STATUSES = ("ENABLED", "DISABLED")
CALIBRATION_STATUSES = ("PROVISIONAL", "CALIBRATED")
MISSING_VALUE_POLICIES = ("ZERO_CONTRIBUTION", "UNAVAILABLE", "EXPLICIT_PENALTY")
COMBINE_RULES = ("PRODUCT", "MIN")

# --- canonical event fields --------------------------------------------------
# Names a registry parameter may list in ``source_fields``. ``fields.py``
# resolves each to a value (or an explicit MISSING marker) for one event.
FIELD_NAMES = frozenset({
    # identity
    "actor.normalized", "actor.email", "actor.username", "account.id",
    "recipients.emails", "device.id",
    # artifact / message identity
    "message.id", "message.references", "thread.id", "attachment.sha256",
    "attachment.names", "file.sha256", "file.name", "file.mime", "file.size",
    # time
    "time.utc", "time.interval", "time.quality", "time.tz_assumption",
    "time.clock_uncertainty_seconds",
    # network
    "net.ip", "net.src_ip", "net.dst_ip", "net.src_port", "net.dst_port",
    "net.protocol", "net.domain", "net.dns_answers", "net.session_id",
    "net.capture_id", "net.user_agent",
    # content
    "content.subject", "content.body", "content.text", "content.url_domains",
    # action
    "event.action", "event.source",
    # provenance
    "prov.source", "prov.parser_confidence", "prov.acquisition_method", "prov.integrity",
    "prov.evidence_id",
})

# --- extraction methods ------------------------------------------------------
# Generic, deterministic building blocks. A parameter selects one and supplies
# options in ``extraction_method``; ``features.py`` implements each.
EXTRACTION_METHODS = frozenset({
    "EXACT_MATCH",            # scalar equality after canonicalisation
    "SET_INTERSECTION",       # fraction/any overlap of two value sets
    "SET_CONTAINS",           # scalar of one event is a member of the other's set (either direction)
    "TOKEN_JACCARD",          # Jaccard similarity of normalised token sets
    "TIME_SEPARATION",        # seconds between effective intervals
    "INTERVAL_OVERLAP",       # effective intervals overlap
    "ORDERED_ACTIONS",        # action pair is in registry ordered pairs and order holds
    "ORDERED_ACTIONS_VIOLATION",  # ordered pair definitely violated given clock intervals
    "ALIAS_MAPPED",           # both identities fall in the same registry alias group
    "ENDPOINT_PAIR",          # (src,dst) endpoint pair equal, either direction
    "CONFLICT_CHECK",         # shared key but differing fact fields
    "IDENTITY_CONFLICT",      # same identity namespace, different value
    "FIELD_QUALITY_MAP",      # map a categorical field to a [0,1] factor
    "FIELD_UNIT_VALUE",       # a field already in [0,1]
    "FIELD_COMPLETENESS",     # fraction of the listed source fields present on an event
    "CLOCK_UNCERTAINTY",      # source clock uncertainty relative to a window
    "ANCHOR_EXACT",           # exact identifier equality plus validation
    "ANCHOR_REFERENCE",       # one event's reference list contains the other's id
    "ANCHOR_SCOPED_EXACT",    # exact identifier valid only inside a namespace
})

NORMALISATION_KINDS = frozenset({
    "BINARY",         # 1.0 if matched else 0.0
    "LINEAR_DECAY",   # max(0, 1 - x / window_seconds)
    "UNIT_PASSTHROUGH",
    "UNIT_FLOOR",     # below ``floor`` -> 0, else rescaled to 0..1
    "UNIT_RESCALE",   # min_factor + (1 - min_factor) * value   (reliability factors)
    "MAP_LOOKUP",     # value comes from the extraction map
})

SCOPE_MODES = ("ALL", "FIRST_PRESENT")  # ANCHOR_SCOPED_EXACT: all scope fields must agree / first present one

COLLISION_KINDS = frozenset({
    "HUB_COUNT",      # discount values that occur in many events of the input (T5 hub formula)
    "COMMON_VALUE",   # discount values listed in registry reference data
})

# Counters a HUB_COUNT collision rule may use.
HUB_COUNTERS = frozenset({"ip", "device", "domain", "account", "filename", "port", "user_agent"})

# Reference-data lists a COMMON_VALUE rule may name.
COMMON_VALUE_LISTS = frozenset({"filenames", "domains", "subjects", "phrases", "ports", "user_agents", "usernames"})

# Candidate-generation indexes a registry may enable (implemented in ``anchors.py``
# / ``scorer.py``). Candidate generation is NOT evidence of a relationship.
CANDIDATE_INDEXES = frozenset({
    "file_hash", "attachment_hash", "message_id", "message_reference", "thread_id",
    "session_id", "account", "email", "username", "domain", "ip", "device",
    "actor_device", "filename", "time_window",
})

# --- fixture contract --------------------------------------------------------
# A fixture is ``{label, events[2], expect, [reference_data], [source_clocks]}``.
# ``expect`` holds any of: value (number), min, max, status.
FIXTURE_CASE_KEYS = frozenset({"label", "events", "expect", "reference_data", "source_clocks"})
FIXTURE_EXPECT_KEYS = frozenset({"value", "min", "max", "status"})
ANCHOR_OUTCOMES = ("ANCHORED", "REJECTED", "NO_MATCH")
EVALUATION_STATUSES = ("EVALUATED", "UNAVAILABLE", "BLOCKED")
