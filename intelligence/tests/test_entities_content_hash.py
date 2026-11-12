"""Regression tests for content-hash versus perceptual-hash semantics."""

import pytest

from intelligence.entities import extract_content_hash, extract_canonical_entities, normalize_file_object


def test_perceptual_hash_is_not_a_content_hash_or_file_object() -> None:
    event = {
        "event_id": "IMG-001",
        "source": "image",
        "action": "image_captured",
        "object": None,
        "raw": {"perceptual_hash": "8000000000000000"},
    }

    assert extract_content_hash(event) is None
    entities = extract_canonical_entities(event)
    assert entities.content_hash is None
    assert entities.file_object is None


def test_cryptographic_content_hash_remains_matchable() -> None:
    digest = "a" * 64
    event = {"object": None, "raw": {"content_hash": digest}}

    assert extract_content_hash(event) == digest


def test_sha256_metadata_remains_matchable() -> None:
    digest = "b" * 64
    event = {"object": None, "raw": {"sha256": digest}}

    assert extract_content_hash(event) == digest


@pytest.mark.parametrize(
    ("metadata_key", "length"),
    [("content_hash", 32), ("file_sha256", 40), ("sha256", 64)],
)
def test_supported_cryptographic_hash_lengths_remain_matchable(
    metadata_key: str,
    length: int,
) -> None:
    digest = "c" * length

    assert extract_content_hash({"object": None, "raw": {metadata_key: digest}}) == digest


def test_invalid_short_content_hash_is_not_matchable() -> None:
    event = {"object": None, "raw": {"content_hash": "not-a-content-hash"}}

    assert extract_content_hash(event) is None


def test_short_hex_and_perceptual_hash_shapes_are_not_file_objects() -> None:
    assert normalize_file_object("abcd1234") is None
    assert normalize_file_object("8000000000000000") is None
