"""Tests for evidence-engine.intake.custody"""
import sys
import os
import importlib.util
import json
import tempfile

# Load the module directly from file
spec = importlib.util.spec_from_file_location(
    "custody",
    os.path.join(os.path.dirname(__file__), '..', 'intake', 'custody.py')
)
custody = importlib.util.module_from_spec(spec)
spec.loader.exec_module(custody)

append_entry = custody.append_entry
verify_log = custody.verify_log


def test_first_entry():
    """Test creating the first entry in a custody log"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        log_path = tmp.name

    try:
        # Add first entry
        entry = append_entry(
            log_path=log_path,
            actor="detective_jones",
            action="collected",
            evidence_id="EVID-001",
            sha256="a" * 64  # 64 character hash
        )

        # Verify the entry
        assert entry["actor"] == "detective_jones"
        assert entry["action"] == "collected"
        assert entry["evidence_id"] == "EVID-001"
        assert entry["sha256"] == "a" * 64
        assert "timestamp" in entry
        # First entry should have all zeros for previous_hash
        assert entry["previous_hash"] == "0" * 64

        # Verify the log is valid
        assert verify_log(log_path) == True

        # Check the file contents
        with open(log_path, 'r') as f:
            lines = f.readlines()
            assert len(lines) == 1
            parsed = json.loads(lines[0].strip())
            assert parsed == entry

    finally:
        os.unlink(log_path)


def test_second_chained_entry():
    """Test that the second entry correctly hashes the first entry"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        log_path = tmp.name

    try:
        # Add first entry
        entry1 = append_entry(
            log_path=log_path,
            actor="detective_jones",
            action="collected",
            evidence_id="EVID-001",
            sha256="a" * 64
        )

        # Add second entry
        entry2 = append_entry(
            log_path=log_path,
            actor="detective_smith",
            action="transferred",
            evidence_id="EVID-001",
            sha256="a" * 64
        )

        # Verify second entry has correct previous_hash
        # The previous_hash should be the hash of the first entry line
        with open(log_path, 'r') as f:
            first_line = f.readline().strip()
            expected_previous_hash = ""
            # We need to compute what the hash should be

        # Instead of trying to compute it manually, let's verify the chain
        assert verify_log(log_path) == True

        # Check that we have two^--^
        with open(log_path, 'r') as f:
            lines = f.readlines()
            assert len(lines) == 2

            # Parse both entries
            first_entry = json.loads(lines[0].strip())
            second_entry = json.loads(lines[1].strip())

            # Verify first entry
            assert first_entry["actor"] == "detective_jones"
            assert first_entry["previous_hash"] == "0" * 64

            # Verify second entry points to first
            # We can't easily compute the hash here, but verify_log will do it for us
            assert second_entry["actor"] == "detective_smith"

    finally:
        os.unlink(log_path)


def test_multiple_entries():
    """Test multiple entries in a custody log"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        log_path = tmp.name

    try:
        # Add three entries
        entry1 = append_entry(log_path, "actor1", "action1", "EVID-001", "a" * 64)
        entry2 = append_entry(log_path, "actor2", "action2", "EVID-001", "a" * 64)
        entry3 = append_entry(log_path, "actor3", "action3", "EVID-001", "a" * 64)

        # Verify the log is valid
        assert verify_log(log_path) == True

        # Check we have three entries
        with open(log_path, 'r') as f:
            lines = f.readlines()
            assert len(lines) == 3

    finally:
        os.unlink(log_path)


def test_valid_verification():
    """Test that a valid log verifies correctly"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        log_path = tmp.name

    try:
        # Start with empty log - should verify as True
        assert verify_log(log_path) == True

        # Add an entry
        append_entry(log_path, "actor", "action", "EVID-001", "a" * 64)

        # Should still verify as True
        assert verify_log(log_path) == True

        # Add another entry
        append_entry(log_path, "actor2", "action2", "EVID-002", "b" * 64)

        # Should still verify as True
        assert verify_log(log_path) == True

    finally:
        os.unlink(log_path)


def test_modified_entry():
    """Test that modifying an entry causes verification to fail"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        log_path = tmp.name

    try:
        # Add two entries
        append_entry(log_path, "actor1", "action1", "EVID-001", "a" * 64)
        append_entry(log_path, "actor2", "action2", "EVID-001", "b" * 64)

        # Verify log is valid
        assert verify_log(log_path) == True

        # Now modify the first line
        with open(log_path, 'r') as f:
            lines = f.readlines()

        # Change something in the first line
        entry = json.loads(lines[0].strip())
        entry["actor"] = "modified_actor"
        lines[0] = json.dumps(entry, sort_keys=True) + '\n'

        # Write back the modified content
        with open(log_path, 'w') as f:
            f.writelines(lines)

        # Verification should now fail
        assert verify_log(log_path) == False

    finally:
        os.unlink(log_path)


def test_modified_previous_hash():
    """Test that modifying previous_hash causes verification to fail"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        log_path = tmp.name

    try:
        # Add two entries so the second one has a non-zero previous_hash
        append_entry(log_path, "actor1", "action1", "EVID-001", "a" * 64)
        append_entry(log_path, "actor2", "action2", "EVID-001", "b" * 64)

        # Verify log is valid
        assert verify_log(log_path) == True

        # Now modify the previous_hash in the second line
        with open(log_path, 'r') as f:
            lines = f.readlines()

        # Change the previous_hash in the second line
        entry = json.loads(lines[1].strip())
        entry["previous_hash"] = "tampered_hash"
        lines[1] = json.dumps(entry, sort_keys=True) + '\n'

        # Write back the modified content
        with open(log_path, 'w') as f:
            f.writelines(lines)

        # Verification should now fail
        assert verify_log(log_path) == False

    finally:
        os.unlink(log_path)


def test_malformed_line():
    """Test that malformed JSON causes verification to fail"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        log_path = tmp.name

    try:
        # Add a valid entry first
        append_entry(log_path, "actor1", "action1", "EVID-001", "a" * 64)

        # Verify log is valid
        assert verify_log(log_path) == True

        # Now append malformed JSON
        with open(log_path, 'a') as f:
            f.write('{"invalid": json}\n')

        # Verification should now fail
        assert verify_log(log_path) == False

    finally:
        os.unlink(log_path)


def test_empty_nonexistent_log():
    """Test that empty/nonexistent log is handled sensibly"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        log_path = tmp.name

    try:
        # File doesn't exist yet - should verify as True
        assert verify_log(log_path) == True

        # Create an empty file
        with open(log_path, 'w') as f:
            pass  # Just create empty file

        # Empty file should verify as True
        assert verify_log(log_path) == True

    finally:
        if os.path.exists(log_path):
            os.unlink(log_path)


if __name__ == "__main__":
    test_first_entry()
    test_second_chained_entry()
    test_multiple_entries()
    test_valid_verification()
    test_modified_entry()
    test_modified_previous_hash()
    test_malformed_line()
    test_empty_nonexistent_log()
    print("All custody tests passed!")

def test_whitespace_tampering_is_detected():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        log_path = tmp.name
    try:
        append_entry(log_path, "actor", "action", "EVID-001", "a" * 64)
        assert verify_log(log_path) is True
        with open(log_path, "r", encoding="utf-8") as f:
            line = f.readline().rstrip("\n")
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(line + " " + "\n")
        assert verify_log(log_path) is False
    finally:
        if os.path.exists(log_path):
            os.unlink(log_path)


def test_blank_line_is_invalid():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        log_path = tmp.name
    try:
        append_entry(log_path, "actor", "action", "EVID-001", "a" * 64)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write("\n")
        assert verify_log(log_path) is False
    finally:
        if os.path.exists(log_path):
            os.unlink(log_path)


def test_deleted_interior_line_is_detected():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        log_path = tmp.name
    try:
        append_entry(log_path, "actor1", "action", "EVID-001", "a" * 64)
        append_entry(log_path, "actor2", "action", "EVID-001", "b" * 64)
        append_entry(log_path, "actor3", "action", "EVID-001", "c" * 64)
        with open(log_path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
        with open(log_path, "w", encoding="utf-8") as handle:
            handle.writelines((lines[0], lines[2]))
        assert verify_log(log_path) is False
    finally:
        if os.path.exists(log_path):
            os.unlink(log_path)


def test_reordered_lines_are_detected():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        log_path = tmp.name
    try:
        append_entry(log_path, "actor1", "action", "EVID-001", "a" * 64)
        append_entry(log_path, "actor2", "action", "EVID-001", "b" * 64)
        append_entry(log_path, "actor3", "action", "EVID-001", "c" * 64)
        with open(log_path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
        with open(log_path, "w", encoding="utf-8") as handle:
            handle.writelines((lines[1], lines[0], lines[2]))
        assert verify_log(log_path) is False
    finally:
        if os.path.exists(log_path):
            os.unlink(log_path)
