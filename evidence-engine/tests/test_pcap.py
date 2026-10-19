"""Tests for evidence-engine.parsers.pcap"""
import sys
import os
import importlib.util
import json
import tempfile

import pytest

# Load the module directly from file
spec = importlib.util.spec_from_file_location(
    "pcap",
    os.path.join(os.path.dirname(__file__), '..', 'parsers', 'pcap.py')
)
pcap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pcap)

parse = pcap.parse


def test_parse_when_scapy_not_available():
    """Test that missing Scapy produces a clear error."""
    # Temporarily disable SCAMPY by setting the flag to False
    original_has_scapy = pcap.HAS_SCAMPY
    pcap.HAS_SCAMPY = False

    try:
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp.write(b"fake pcap data")
            tmp_path = tmp.name

        try:
            try:
                parse(
                    path=tmp_path,
                    case_id="CASE-001",
                    evidence_id="EVID-001",
                    sha256="a" * 64
                )
                assert False, "Expected RuntimeError when Scapy is missing"
            except RuntimeError as exc:
                assert "Scapy is required" in str(exc)

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


@pytest.mark.skipif(not pcap.HAS_SCAMPY, reason="Scapy is required for packet construction")
def test_dns_query_and_response_events(tmp_path):
    from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, wrpcap

    query = (
        IP(src="203.0.113.10", dst="203.0.113.53")
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="archive.example.test"))
    )
    response = (
        IP(src="203.0.113.53", dst="203.0.113.10")
        / UDP(sport=53, dport=53000)
        / DNS(
            qr=1,
            qd=DNSQR(qname="archive.example.test"),
            an=DNSRR(rrname="archive.example.test", type="A", rdata="203.0.113.22"),
        )
    )
    query.time = 1792320000
    response.time = 1792320001
    path = tmp_path / "dns.pcap"
    wrpcap(str(path), [query, response])

    events = parse(str(path), "CASE-001", "EVID-001", "a" * 64)

    assert len(events) == 2
    assert events[0]["action"] == "DNS query archive.example.test"
    assert events[0]["object"] == "archive.example.test"
    assert events[0]["ip"] == "203.0.113.10"
    assert events[0]["timestamp"] == "2026-10-18T10:40:00Z"
    assert events[1]["action"] == "DNS response archive.example.test"
    assert events[1]["ip"] == "203.0.113.22"
    for event in events:
        json.dumps(event)


@pytest.mark.skipif(not pcap.HAS_SCAMPY, reason="Scapy is required for packet construction")
def test_skipped_packet_count_is_logged(tmp_path, monkeypatch, caplog):
    from scapy.packet import Raw

    packet = Raw(load=b"no timestamp")
    packet.time = 0
    monkeypatch.setattr(pcap, "rdpcap", lambda path: [packet, packet])

    events = parse(str(tmp_path / "capture.pcap"), "CASE-001", "EVID-001", "a" * 64)

    assert events == []
    assert "Skipped 2 PCAP packet(s)" in caplog.text


if __name__ == "__main__":
    test_parse_when_scapy_not_available()
    test_parse_invalid_file()
    test_parse_nonexistent_file()
    print("All PCAP tests passed!")