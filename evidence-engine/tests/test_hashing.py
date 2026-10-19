"""Tests for evidence-engine.intake.hashing"""
import sys
import os
import importlib.util

# Load the module directly from file
spec = importlib.util.spec_from_file_location(
    "hashing",
    os.path.join(os.path.dirname(__file__), '..', 'intake', 'hashing.py')
)
hashing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hashing)

sha256_file = hashing.sha256_file
intake_record = hashing.intake_record

import hashlib
import tempfile


def test_sha256_file_correctness():
    """Test that sha256_file produces correct hash against hashlib"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"test data for hashing")
        tmp_path = tmp.name

    try:
        # Our implementation
        hash1 = sha256_file(tmp_path)

        # Standard library implementation
        hash2 = hashlib.sha256(b"test data for hashing").hexdigest()

        assert hash1 == hash2
    finally:
        os.unlink(tmp_path)


def test_sha256_file_chunked():
    """Test that sha256_file works correctly with chunked reading"""
    # Create a file larger than the default chunk size (1MB)
    data = b"A" * (1024 * 1024 + 500)  # 1MB + 500 bytes

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    try:
        hash1 = sha256_file(tmp_path)
        hash2 = hashlib.sha256(data).hexdigest()
        assert hash1 == hash2
    finally:
        os.unlink(tmp_path)


def test_intake_record_fields():
    """Test that intake_record returns all expected fields"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"test data")
        tmp_path = tmp.name

    try:
        record = intake_record(tmp_path, 1)

        # Check all expected fields are present
        assert "evidence_id" in record
        assert "filename" in record
        assert "size_bytes" in record
        assert "sha256" in record
        assert "intake_time" in record

        # Check evidence ID format
        assert record["evidence_id"] == "EVID-001"

        # Check filename
        assert record["filename"] == os.path.basename(tmp_path)

        # Check size
        assert record["size_bytes"] == len(b"test data")

        # Check SHA-256
        expected_hash = hashlib.sha256(b"test data").hexdigest()
        assert record["sha256"] == expected_hash

        # Check intake_time is recent (within last 5 seconds)
        from datetime import datetime, timezone
        intake_time = datetime.fromisoformat(record["intake_time"])
        now = datetime.now(timezone.utc)
        diff = abs((now - intake_time).total_seconds())
        assert diff < 5

    finally:
        os.unlink(tmp_path)


def test_intake_record_evidence_id_format():
    """Test that evidence IDs follow EVID-001 style format"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"test")
        tmp_path = tmp.name

    try:
        # Test sequence 1
        record1 = intake_record(tmp_path, 1)
        assert record1["evidence_id"] == "EVID-001"

        # Test sequence 23
        record23 = intake_record(tmp_path, 23)
        assert record23["evidence_id"] == "EVID-023"

        # Test sequence 999
        record999 = intake_record(tmp_path, 999)
        assert record999["evidence_id"] == "EVID-999"

    finally:
        os.unlink(tmp_path)


def test_intake_record_missing_file():
    """Test that intake_record raises appropriate error for missing file"""
    try:
        intake_record("/non/existent/file.txt", 1)
        assert False, "Expected OSError"
    except OSError:
        pass  # Expected


if __name__ == "__main__":
    test_sha256_file_correctness()
    test_sha256_file_chunked()
    test_intake_record_fields()
    test_intake_record_evidence_id_format()
    test_intake_record_missing_file()
    print("All tests passed!")