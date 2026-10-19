"""Role 1: parser for network capture (PCAP, Scapy).

Parses PCAP files using Scapy to extract basic packet information.
Does not attempt to be a full network forensics parser.

For each packet with a timestamp:
- source = "pcap"
- timestamp = packet timestamp (from packet.time)
- action = descriptive string based on packet layers/protocols
- artifact_ref = "{filename}#packet={packet_index}" (0-indexed)
- raw = safe normalized packet metadata (layers, lengths, etc.)
- Extracts: src IP, dst IP, protocol when available from IP layer

If Scapy is not available, returns empty list (graceful degradation).
"""
from __future__ import annotations

import os
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from parsers.timestamps import normalize_timestamp

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR
    from scapy.packet import Packet
    HAS_SCAMPY = True
except ImportError:
    HAS_SCAMPY = False


logger = logging.getLogger(__name__)


def _safe_str(obj: Any) -> str:
    """Safely convert object to string for serialization."""
    try:
        return str(obj)
    except Exception:
        return "<unserializable>"


def _normalize_packet_info(packet: Packet, packet_idx: int) -> Dict[str, Any]:
    """Extract safe, serializable information from a packet."""
    info = {
        "packet_number": packet_idx,
        "time": float(getattr(packet, 'time', 0)),
        "layers": [],
        "length": len(packet) if hasattr(packet, '__len__') else 0
    }

    # Extract layers safely
    layer = packet
    layer_count = 0
    while layer and layer_count < 10:  # Prevent infinite loops
        layer_name = _safe_str(layer.__class__.__name__)
        if layer_name not in info["layers"]:
            info["layers"].append(layer_name)

        # Try to get payload
        try:
            layer = layer.payload
        except AttributeError:
            break
        layer_count += 1

    # Extract IP addresses and protocol if available
    src_ip = None
    dst_ip = None
    protocol = None

    if IP in packet or IPv6 in packet:
        ip_layer = packet[IP] if IP in packet else packet[IPv6]
        src_ip = _safe_str(getattr(ip_layer, 'src', None))
        dst_ip = _safe_str(getattr(ip_layer, 'dst', None))
        protocol = _safe_str(getattr(ip_layer, 'proto', None))

        # Try to get protocol name
        if protocol and protocol.isdigit():
            try:
                proto_num = int(protocol)
                proto_map = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP"}
                protocol = proto_map.get(proto_num, protocol)
            except ValueError:
                pass

    # Extract transport layer info
    if TCP in packet:
        tcp = packet[TCP]
        info["tcp_sport"] = getattr(tcp, 'sport', None)
        info["tcp_dport"] = getattr(tcp, 'dport', None)
        info["tcp_flags"] = _safe_str(getattr(tcp, 'flags', None))
    elif UDP in packet:
        udp = packet[UDP]
        info["udp_sport"] = getattr(udp, 'sport', None)
        info["udp_dport"] = getattr(udp, 'dport', None)
    elif ICMP in packet:
        icmp = packet[ICMP]
        info["icmp_type"] = getattr(icmp, 'type', None)
        info["icmp_code"] = getattr(icmp, 'code', None)
    elif ARP in packet:
        arp = packet[ARP]
        info["arp_op"] = getattr(arp, 'op', None)
        info["arp_psrc"] = getattr(arp, 'psrc', None)
        info["arp_pdst"] = getattr(arp, 'pdst', None)
        info["arp_hwsrc"] = getattr(arp, 'hwsrc', None)
        info["arp_hwdst"] = getattr(arp, 'hwdst', None)

    info["src_ip"] = src_ip
    info["dst_ip"] = dst_ip
    info["protocol"] = protocol

    if HAS_SCAMPY and DNS in packet:
        dns = packet[DNS]
        query_name = None
        if dns.qdcount and DNSQR in packet:
            raw_name = packet[DNSQR].qname
            if isinstance(raw_name, bytes):
                query_name = raw_name.decode("ascii", errors="replace").rstrip(".")
            else:
                query_name = _safe_str(raw_name).rstrip(".")
        answer_ips = []
        answer = dns.an
        for _ in range(int(dns.ancount or 0)):
            if not answer:
                break
            record_type = getattr(answer, "type", None)
            if record_type in (1, 28):
                answer_ips.append(_safe_str(getattr(answer, "rdata", None)))
            answer = answer.payload
        info["dns_query"] = query_name
        info["dns_answers"] = answer_ips
        info["dns_response"] = bool(dns.qr)

    return info


def _describe_packet_action(packet_info: Dict[str, Any]) -> str:
    """Generate a descriptive action string from packet information."""
    layers = packet_info.get("layers", [])
    action_parts = []

    # Start with the most specific layer info
    if "TCP" in layers:
        sport = packet_info.get("tcp_sport")
        dport = packet_info.get("tcp_dport")
        if sport is not None and dport is not None:
            action_parts.append(f"TCP {sport}->{dport}")
        else:
            action_parts.append("TCP")
    elif "UDP" in layers:
        sport = packet_info.get("udp_sport")
        dport = packet_info.get("udp_dport")
        if sport is not None and dport is not None:
            action_parts.append(f"UDP {sport}->{dport}")
        else:
            action_parts.append("UDP")
    elif "ICMP" in layers:
        icmp_type = packet_info.get("icmp_type")
        icmp_code = packet_info.get("icmp_code")
        if icmp_type is not None and icmp_code is not None:
            action_parts.append(f"ICMP type={icmp_type} code={icmp_code}")
        else:
            action_parts.append("ICMP")
    elif "ARP" in layers:
        op = packet_info.get("arp_op")
        if op is not None:
            op_map = {1: "request", 2: "reply"}
            op_str = op_map.get(op, str(op))
            action_parts.append(f"ARP {op_str}")
        else:
            action_parts.append("ARP")
    else:
        # Fallback to general layer description
        if layers:
            action_parts.append(" + ".join(layers))
        else:
            action_parts.append("unknown")

    # Add IP info if available
    src_ip = packet_info.get("src_ip")
    dst_ip = packet_info.get("dst_ip")
    if src_ip and dst_ip and src_ip != "<unserializable>" and dst_ip != "<unserializable>":
        action_parts.append(f"{src_ip} -> {dst_ip}")

    return " ".join(action_parts)


def parse(path: str, case_id: str, evidence_id: str, sha256: str) -> List[Dict[str, Any]]:
    """Parse PCAP file and return Events.

    Args:
        path: Path to the PCAP file
        case_id: Case identifier
        evidence_id: Evidence identifier
        sha256: SHA-256 hash of the source file

    Returns:
        List of Event dictionaries conforming to contracts/event.schema.json
        (empty list if Scapy is not available or file cannot be read)

    Raises:
        ValueError: For invalid PCAP files when Scapy is available
    """
    if not HAS_SCAMPY:
        raise RuntimeError("Scapy is required to parse PCAP evidence; install scapy")

    try:
        # Read the PCAP file
        packets = rdpcap(path)
    except Exception as e:
        raise ValueError(f"Cannot read PCAP file: {e}")

    events = []
    skipped_packets = 0
    filename = path.split('/')[-1].split('\\')[-1]

    for packet_idx, packet in enumerate(packets):
        try:
            # Extract packet information
            packet_info = _normalize_packet_info(packet, packet_idx)

            # Skip packets without usable timestamp
            timestamp_val = packet_info.get("time", 0)
            if timestamp_val <= 0:
                skipped_packets += 1
                continue

            # Convert timestamp to ISO format
            timestamp = normalize_timestamp(
                datetime.fromtimestamp(timestamp_val, tz=timezone.utc).isoformat()
            )

            # Build artifact_ref
            artifact_ref = f"{filename}#packet={packet_idx}"

            # Build the event
            dns_query = packet_info.get("dns_query")
            dns_answers = packet_info.get("dns_answers", [])
            dns_response = packet_info.get("dns_response", False)
            if dns_query:
                action = "DNS response" if dns_response else "DNS query"
                action = f"{action} {dns_query}"
                object_value = dns_query
                event_ip = next(
                    (answer for answer in dns_answers if answer and answer != "<unserializable>"),
                    packet_info.get("src_ip"),
                )
            else:
                action = _describe_packet_action(packet_info)
                object_value = packet_info.get("protocol")
                event_ip = packet_info.get("src_ip")

            event = {
                "event_id": f"EV-{packet_idx + 1:06d}",  # Sequential ID starting from 1
                "case_id": case_id,
                "evidence_id": evidence_id,
                "artifact_ref": artifact_ref,
                "sha256": sha256,
                "timestamp": timestamp,
                "source": "pcap",
                "action": action,
                "raw": packet_info  # Safe normalized metadata
            }
            if object_value:
                event["object"] = object_value

            # Add optional fields if available
            if event_ip and event_ip != "<unserializable>":
                event["ip"] = event_ip
            # Note: The event schema doesn't have a separate dst_ip field,
            # but we could put it in object or raw if needed

            events.append(event)

        except Exception as e:
            skipped_packets += 1
            logger.warning("Skipping PCAP packet %d in %s: %s", packet_idx, filename, e)
            continue

    if skipped_packets:
        logger.warning("Skipped %d PCAP packet(s) in %s", skipped_packets, filename)
    return events