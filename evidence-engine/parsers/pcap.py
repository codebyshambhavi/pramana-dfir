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
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP
    from scapy.packet import Packet
    HAS_SCAMPY = True
except ImportError:
    HAS_SCAMPY = False


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
        "time": getattr(packet, 'time', 0),
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
        # If Scapy is not available, we cannot parse PCAPs
        # Return empty list rather than failing, as this might be expected
        return []

    try:
        # Read the PCAP file
        packets = rdpcap(path)
    except Exception as e:
        raise ValueError(f"Cannot read PCAP file: {e}")

    events = []
    filename = path.split('/')[-1].split('\\')[-1]

    for packet_idx, packet in enumerate(packets):
        try:
            # Extract packet information
            packet_info = _normalize_packet_info(packet, packet_idx)

            # Skip packets without usable timestamp
            timestamp_val = packet_info.get("time", 0)
            if timestamp_val <= 0:
                continue

            # Convert timestamp to ISO format
            timestamp = datetime.fromtimestamp(timestamp_val, tz=timezone.utc).isoformat()

            # Build artifact_ref
            artifact_ref = f"{filename}#packet={packet_idx}"

            # Build the event
            event = {
                "event_id": f"EV-{packet_idx + 1:06d}",  # Sequential ID starting from 1
                "case_id": case_id,
                "evidence_id": evidence_id,
                "artifact_ref": artifact_ref,
                "sha256": sha256,
                "timestamp": timestamp,
                "source": "pcap",
                "action": _describe_packet_action(packet_info),
                "raw": packet_info  # Safe normalized metadata
            }

            # Add optional fields if available
            src_ip = packet_info.get("src_ip")
            dst_ip = packet_info.get("dst_ip")
            if src_ip and src_ip != "<unserializable>":
                event["ip"] = src_ip  # Using ip field for source IP as per schema
            # Note: The event schema doesn't have a separate dst_ip field,
            # but we could put it in object or raw if needed

            protocol = packet_info.get("protocol")
            if protocol and protocol != "<unserializable>":
                # Put protocol in object field if it's meaningful
                if event.get("object") is None:
                    event["object"] = protocol
                # Otherwise it's already set by _describe_packet_action

            events.append(event)

        except Exception as e:
            # Skip problematic packets but continue processing
            # In a real implementation, we might want to log this
            continue

    return events