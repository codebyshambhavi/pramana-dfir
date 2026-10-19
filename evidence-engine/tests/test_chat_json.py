"""Tests for evidence-engine.parsers.chat_json"""
import sys
import os
import importlib.util
import tempfile
import json

# Load the module directly from file
spec = importlib.util.spec_from_file_location(
    "chat_json",
    os.path.join(os.path.dirname(__file__), '..', 'parsers', 'chat_json.py')
)
chat_json = importlib.util.module_from_spec(spec)
spec.loader.exec_module(chat_json)

parse = chat_json.parse


def test_valid_json_array():
    """Test parsing a valid JSON array"""
    json_data = [
        {
            "timestamp": "2023-01-01T10:00:00Z",
            "action": "message_sent",
            "actor": "alice",
            "device": "phone_1",
            "object": "Hello world!",
            "ip": "192.168.1.10"
        },
        {
            "timestamp": "2023-01-01T10:05:00Z",
            "action": "message_received",
            "actor": "bob",
            "device": "laptop_2",
            "object": "Hi Alice!",
            "ip": "192.168.1.20"
        },
        {
            "timestamp": "2023-01-01T10:10:00Z",
            "action": "user_joined",
            "actor": "charlie"
            # Missing optional fields
        }
    ]

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        json.dump(json_data, tmp)
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

        # Debug print
        print(f"First event: {events[0]}")

        # Check first event
        assert events[0]["event_id"] == "EV-000001"
        assert events[0]["case_id"] == "CASE-001"
        assert events[0]["evidence_id"] == "EVID-001"
        assert events[0]["artifact_ref"] == os.path.basename(tmp_path) + "#item=0"
        assert events[0]["sha256"] == "a" * 64
        assert events[0]["timestamp"] == "2023-01-01T10:00:00Z"
        assert events[0]["source"] == "chat"
        assert events[0]["action"] == "message_sent"
        assert events[0]["object"] == "Hello world!"
        assert events[0]["actor"] == "alice"
        assert events[0]["device"] == "phone_1"
        assert events[0]["ip"] == "192.168.1.10"
        assert events[0]["raw"] == json_data[0]

        # Check second event
        assert events[1]["event_id"] == "EV-000002"
        assert events[1]["case_id"] == "CASE-001"
        assert events[1]["evidence_id"] == "EVID-001"
        assert events[1]["artifact_ref"] == os.path.basename(tmp_path) + "#item=1"
        assert events[1]["action"] == "message_received"
        assert events[1]["object"] == "Hi Alice!"
        assert events[1]["actor"] == "bob"
        assert events[1]["device"] == "laptop_2"
        assert events[1]["ip"] == "192.168.1.20"

        # Check third event (with missing optional fields)
        assert events[2]["event_id"] == "EV-000003"
        assert events[2]["case_id"] == "CASE-001"
        assert events[2]["evidence_id"] == "EVID-001"
        assert events[2]["artifact_ref"] == os.path.basename(tmp_path) + "#item=2"
        assert events[2]["action"] == "user_joined"
        assert events[2]["actor"] == "charlie"
        # Optional fields should not be present when missing/null/empty
        assert "device" not in events[2] or events[2].get("device") is None
        assert "object" not in events[2] or events[2].get("object") is None
        assert "ip" not in events[2] or events[2].get("ip") is None

    finally:
        os.unlink(tmp_path)


def test_artifact_ref():
    """Test that artifact_ref correctly identifies the JSON item"""
    json_data = [
        {
            "timestamp": "2023-01-01T10:00:00Z",
            "action": "test"
        }
    ]

    with tempfile.NamedTemporaryFile(mode='w', suffix='chat.json', delete=False) as tmp:
        json.dump(json_data, tmp)
        tmp_path = tmp.name

    try:
        events = parse(
            path=tmp_path,
            case_id="CASE-001",
            evidence_id="EVID-001",
            sha256="a" * 64
        )

        assert len(events) == 1
        expected_ref = os.path.basename(tmp_path) + "#item=0"
        assert events[0]["artifact_ref"] == expected_ref

    finally:
        os.unlink(tmp_path)


def test_source():
    """Test that source is correctly set to 'chat'"""
    json_data = [
        {
            "timestamp": "2023-01-01T10:00:00Z",
            "action": "test"
        }
    ]

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        json.dump(json_data, tmp)
        tmp_path = tmp.name

    try:
        events = parse(
            path=tmp_path,
            case_id="CASE-001",
            evidence_id="EVID-001",
            sha256="a" * 64
        )

        assert len(events) == 1
        assert events[0]["source"] == "chat"

    finally:
        os.unlink(tmp_path)


def test_raw_preservation():
    """Test that raw field preserves original JSON object"""
    json_data = [
        {
            "timestamp": "2023-01-01T10:00:00Z",
            "action": "test",
            "actor": "user",
            "custom_field": "custom_value"
        }
    ]

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        json.dump(json_data, tmp)
        tmp_path = tmp.name

    try:
        events = parse(
            path=tmp_path,
            case_id="CASE-001",
            evidence_id="EVID-001",
            sha256="a" * 64
        )

        assert len(events) == 1
        # Raw should contain the original object
        assert events[0]["raw"] == json_data[0]

    finally:
        os.unlink(tmp_path)


def test_malformed_json():
    """Test that malformed JSON raises ValueError"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        tmp.write('{"invalid": json}')  # Invalid JSON
        tmp_path = tmp.name

    try:
        try:
            parse(
                path=tmp_path,
                case_id="CASE-001",
                evidence_id="EVID-001",
                sha256="a" * 64
            )
            assert False, "Expected ValueError for malformed JSON"
        except ValueError as e:
            assert "Invalid JSON" in str(e)

    finally:
        os.unlink(tmp_path)


def test_not_json_array():
    """Test that non-array JSON raises ValueError"""
    json_data = {
        "timestamp": "2023-01-01T10:00:00Z",
        "action": "test"
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        json.dump(json_data, tmp)
        tmp_path = tmp.name

    try:
        try:
            parse(
                path=tmp_path,
                case_id="CASE-001",
                evidence_id="EVID-001",
                sha256="a" * 64
            )
            assert False, "Expected ValueError for non-array JSON"
        except ValueError as e:
            assert "Expected JSON array at root" in str(e)

    finally:
        os.unlink(tmp_path)


def test_missing_required_field():
    """Test that missing required field raises ValueError"""
    json_data = [
        {
            "timestamp": "2023-01-01T10:00:00Z"
            # Missing "action"
        }
    ]

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        json.dump(json_data, tmp)
        tmp_path = tmp.name

    try:
        try:
            parse(
                path=tmp_path,
                case_id="CASE-001",
                evidence_id="EVID-001",
                sha256="a" * 64
            )
            assert False, "Expected ValueError for missing required field"
        except ValueError as e:
            assert "missing or empty 'action'" in str(e)

    finally:
        os.unlink(tmp_path)


def test_empty_required_field():
    """Test that empty required field raises ValueError"""
    json_data = [
        {
            "timestamp": "2023-01-01T10:00:00Z",
            "action": ""  # Empty action
        }
    ]

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        json.dump(json_data, tmp)
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
            assert "missing or empty 'action'" in str(e)

    finally:
        os.unlink(tmp_path)


if __name__ == "__main__":
    test_valid_json_array()
    test_artifact_ref()
    test_source()
    test_raw_preservation()
    test_malformed_json()
    test_not_json_array()
    test_missing_required_field()
    test_empty_required_field()
    print("All chat JSON tests passed!")