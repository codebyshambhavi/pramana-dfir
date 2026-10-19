"""Tests for evidence-engine.parsers.log_csv"""
import sys
import os
import importlib.util
import tempfile
import csv

# Load the module directly from file
spec = importlib.util.spec_from_file_location(
    "log_csv",
    os.path.join(os.path.dirname(__file__), '..', 'parsers', 'log_csv.py')
)
log_csv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(log_csv)

parse = log_csv.parse


def test_valid_multi_row_csv():
    """Test parsing a valid multi-row CSV"""
    csv_content = """timestamp,action,actor,device,ip,object
2023-01-01T10:00:00Z,login,john_doe,laptop_1,192.168.1.1,/home/john
2023-01-01T10:05:00Z,file_access,jane_smith,phone_2,192.168.1.2,/shared/document.pdf
2023-01-01T10:10:00Z,process_start,,tablet_3,,/usr/bin/app
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
        tmp.write(csv_content)
        tmp_path = tmp.name

    try:
        events = parse(
            path=tmp_path,
            case_id="CASE-001",
            evidence_id="EVID-001",
            sha256="a" * 64
        )

        # Should have 3 events
        assert len(events) == 3

        # Check first event
        assert events[0]["event_id"] == "EV-000001"
        assert events[0]["case_id"] == "CASE-001"
        assert events[0]["evidence_id"] == "EVID-001"
        assert events[0]["artifact_ref"] == os.path.basename(tmp_path) + "#row=1"
        assert events[0]["sha256"] == "a" * 64
        assert events[0]["timestamp"] == "2023-01-01T10:00:00Z"
        assert events[0]["source"] == "log"
        assert events[0]["action"] == "login"
        assert events[0]["object"] == "/home/john"
        assert events[0]["actor"] == "john_doe"
        assert events[0]["device"] == "laptop_1"
        assert events[0]["ip"] == "192.168.1.1"
        assert events[0]["raw"]["timestamp"] == "2023-01-01T10:00:00Z"
        assert events[0]["raw"]["action"] == "login"
        assert events[0]["raw"]["actor"] == "john_doe"
        assert events[0]["raw"]["device"] == "laptop_1"
        assert events[0]["raw"]["ip"] == "192.168.1.1"
        assert events[0]["raw"]["object"] == "/home/john"

        # Check second event
        assert events[1]["event_id"] == "EV-000002"
        assert events[1]["artifact_ref"] == os.path.basename(tmp_path) + "#row=2"
        assert events[1]["action"] == "file_access"
        assert events[1]["object"] == "/shared/document.pdf"
        assert events[1]["actor"] == "jane_smith"
        assert events[1]["device"] == "phone_2"
        assert events[1]["ip"] == "192.168.1.2"

        # Check third event (with empty optional fields)
        assert events[2]["event_id"] == "EV-000003"
        assert events[2]["artifact_ref"] == os.path.basename(tmp_path) + "#row=3"
        assert events[2]["action"] == "process_start"
        assert events[2]["object"] == "/usr/bin/app"
        # Optional fields should not be present when empty
        assert "actor" not in events[2] or events[2].get("actor") is None
        assert "device" in events[2] and events[2]["device"] == "tablet_3"
        assert "ip" not in events[2] or events[2].get("ip") is None

    finally:
        os.unlink(tmp_path)


def test_artifact_ref():
    """Test that artifact_ref correctly identifies the CSV row"""
    csv_content = """timestamp,action
2023-01-01T10:00:00Z,login
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='system.log.csv', delete=False) as tmp:
        tmp.write(csv_content)
        tmp_path = tmp.name

    try:
        events = parse(
            path=tmp_path,
            case_id="CASE-001",
            evidence_id="EVID-001",
            sha256="a" * 64
        )

        assert len(events) == 1
        expected_ref = os.path.basename(tmp_path) + "#row=1"
        assert events[0]["artifact_ref"] == expected_ref

    finally:
        os.unlink(tmp_path)


def test_source():
    """Test that source is correctly set to 'log'"""
    csv_content = """timestamp,action
2023-01-01T10:00:00Z,login
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
        tmp.write(csv_content)
        tmp_path = tmp.name

    try:
        events = parse(
            path=tmp_path,
            case_id="CASE-001",
            evidence_id="EVID-001",
            sha256="a" * 64
        )

        assert len(events) == 1
        assert events[0]["source"] == "log"

    finally:
        os.unlink(tmp_path)


def test_raw_preservation():
    """Test that raw field preserves original row fields"""
    csv_content = """timestamp,action,actor,device,ip,object,extra_field
2023-01-01T10:00:00Z,login,john_doe,laptop_1,192.168.1.1,/home/john,extra_value
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
        tmp.write(csv_content)
        tmp_path = tmp.name

    try:
        events = parse(
            path=tmp_path,
            case_id="CASE-001",
            evidence_id="EVID-001",
            sha256="a" * 64
        )

        assert len(events) == 1
        # Raw should contain all original fields
        raw = events[0]["raw"]
        assert raw["timestamp"] == "2023-01-01T10:00:00Z"
        assert raw["action"] == "login"
        assert raw["actor"] == "john_doe"
        assert raw["device"] == "laptop_1"
        assert raw["ip"] == "192.168.1.1"
        assert raw["object"] == "/home/john"
        assert raw["extra_field"] == "extra_value"

    finally:
        os.unlink(tmp_path)


def test_missing_required_column():
    """Test that missing required column raises ValueError"""
    csv_content = """timestamp
2023-01-01T10:00:00Z
"""  # Missing 'action' column

    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
        tmp.write(csv_content)
        tmp_path = tmp.name

    try:
        try:
            parse(
                path=tmp_path,
                case_id="CASE-001",
                evidence_id="EVID-001",
                sha256="a" * 64
            )
            assert False, "Expected ValueError for missing required column"
        except ValueError as e:
            assert "Missing required columns" in str(e)
            assert "action" in str(e)

    finally:
        os.unlink(tmp_path)


def test_empty_required_field():
    """Test that empty required field raises ValueError"""
    csv_content = """timestamp,action
2023-01-01T10:00:00Z,
"""  # Empty action

    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as tmp:
        tmp.write(csv_content)
        tmp_path = tmp.name

    try:
        try:
            parse(
                path=tmp_path,
                case_id="CASE-001",
                evidence_id="EVID-001",
                sha256="a" * 64
            )
            assert False, "Expected ValueError for empty required field"
        except ValueError as e:
            assert "missing required field value" in str(e)

    finally:
        os.unlink(tmp_path)


if __name__ == "__main__":
    test_valid_multi_row_csv()
    test_artifact_ref()
    test_source()
    test_raw_preservation()
    test_missing_required_column()
    test_empty_required_field()
    print("All log CSV tests passed!")