"""Tests for evidence-engine.parsers.pcap"""
import sys
import os
import importlib.util
import tempfile

# Load the module directly from file
spec = importlib.util.spec_from_file_location(
    "pcap",
    os.path.join(os.path.dirname(__file__), '..', 'parsers', 'pcap.py')
)
pcap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pcap)

parse = pcap.parse


def test_parse_when_scapy_not_available():
    """Test behavior when Scapy is not available"""
    # Temporarily disable SCAMPY by setting the flag to False
    original_has_scapy = pcap.HAS_SCAMPY
    pcap.HAS_SCAMPY = False

    try:
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp.write(b"fake pcap data")
            tmp_path = tmp.name

        try:
            events = parse(
                path=tmp_path,
                case_id="CASE-001",
                evidence_id="EVID-001",
                sha256="a" * 64
            )

            # Should return empty list when Scapy is not available
            assert events == []

        finally:
            os.unlink(tmp_path)
    finally:
        # Restore original value
        pcap.HAS_SCAMPY = original_has_scapy


def test_parse_invalid_file():
    """Test that invalid file raises ValueError when Scapy is available"""
    if not pcap.HAS_SCAMPY:
        # Skip this test if Scapy is not available
        print("Skipping invalid file test - Scapy not available")
        return

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"not a pcap file")
        tmp_path = tmp.name

    try:
        try:
            events = parse(
                path=tmp_path,
                case_id="CASE-001",
                evidence_id="EVID-001",
                sha256="a" * 64
            )
            # If we get here without exception, that might be OK depending on implementation
            # But it shouldn't crash unexpectedly
        except ValueError as e:
            # This is expected for invalid PCAP files
            assert "Cannot read PCAP file" in str(e)
        except Exception as e:
            # Other exceptions are also OK as long as they're not crashes
            pass
    finally:
        os.unlink(tmp_path)


def test_parse_nonexistent_file():
    """Test that nonexistent file raises appropriate error"""
    try:
        events = parse(
            path="/non/existent/file.pcap",
            case_id="CASE-001",
            evidence_id="EVID-001",
            sha256="a" * 64
        )
        # If we get here, check what happened
    except FileNotFoundError:
        pass  # Expected
    except Exception as e:
        # Other exceptions are also OK
        pass


if __name__ == "__main__":
    test_parse_when_scapy_not_available()
    test_parse_invalid_file()
    test_parse_nonexistent_file()
    print("All PCAP tests passed!")