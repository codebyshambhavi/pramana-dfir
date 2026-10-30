"""Canonical action vocabulary for Event.action.

Parsers copy ``action`` from heterogeneous sources ("archive_created",
"upload", ...). Downstream rules (``intelligence``) match on a small canonical
set, so a synonym that is not mapped here silently never matches. Only the
synonyms listed below are rewritten; every other action passes through
unchanged. The original value is always preserved in ``Event.raw``.
"""
from __future__ import annotations

# canonical action -> the synonyms seen in real source data (lower-case lookup)
_SYNONYMS: dict[str, tuple[str, ...]] = {
    "archive_create": ("archive_created",),
    "file_upload": ("upload",),
}

CANONICAL_ACTIONS: frozenset[str] = frozenset(_SYNONYMS)

_LOOKUP: dict[str, str] = {
    synonym: canonical
    for canonical, synonyms in _SYNONYMS.items()
    for synonym in (canonical, *synonyms)
}


def canonical_action(raw_action: str) -> str:
    """Return the canonical action for ``raw_action``.

    Known synonyms (case-insensitive, surrounding whitespace ignored) map to
    their canonical form; unknown actions are returned stripped but otherwise
    unchanged. Raises ``ValueError`` for an empty action.
    """
    if not isinstance(raw_action, str) or not raw_action.strip():
        raise ValueError("action must be a non-empty string")
    stripped = raw_action.strip()
    return _LOOKUP.get(stripped.lower(), stripped)
