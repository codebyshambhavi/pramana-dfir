"""Generate deterministic synthetic evidence for sample_case_001."""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from fractions import Fraction
from pathlib import Path

from PIL import ExifTags, Image
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, wrpcap


CASE_DIR = Path(__file__).resolve().parent
ACTOR = "mira.chen"
LAPTOP = "field-laptop-07"
PHONE = "field-phone-07"
SYNTHETIC_IP = "203.0.113.42"
DEVICE_GPS = {"lat": 40.7128, "lon": -74.0060}
IP_LOCATION = {"lat": 38.9072, "lon": -77.0369}
PHOTO_GPS = {"lat": 37.7749, "lon": -122.4194}


def _write_csv(path: Path, headers: list[str], rows: list[list[str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(headers)
        writer.writerows(rows)


def _dms(value: float) -> tuple[Fraction, Fraction, Fraction]:
    absolute = abs(value)
    degrees = int(absolute)
    minutes_float = (absolute - degrees) * 60
    minutes = int(minutes_float)
    seconds = round((minutes_float - minutes) * 60 * 10000)
    return (Fraction(degrees), Fraction(minutes), Fraction(seconds, 10000))


def _write_photo(path: Path, timestamp: str, gps: dict[str, float] | None) -> None:
    image = Image.new("RGB", (96, 64), (68, 105, 91))
    exif = Image.Exif()
    exif[ExifTags.Base.Make] = "Northstar Mobile"
    exif[ExifTags.Base.Model] = "FieldPhone 7"
    exif[ExifTags.Base.DateTimeOriginal] = timestamp.replace("-", ":", 2).replace("T", " ").rstrip("Z")

    if gps:
        gps_tags = {value: key for key, value in ExifTags.GPSTAGS.items()}
        gps_ifd = {
            gps_tags["GPSLatitudeRef"]: "N" if gps["lat"] >= 0 else "S",
            gps_tags["GPSLatitude"]: _dms(gps["lat"]),
            gps_tags["GPSLongitudeRef"]: "E" if gps["lon"] >= 0 else "W",
            gps_tags["GPSLongitude"]: _dms(gps["lon"]),
        }
        exif[ExifTags.IFD.GPSInfo] = gps_ifd

    image.save(path, format="JPEG", quality=90, exif=exif)


def _epoch(timestamp: str) -> float:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()


def generate_case() -> None:
    """Write all synthetic evidence files with fixed timestamps and metadata."""
    chat = [
        {
            "timestamp": "2026-10-18T02:23:00Z",
            "action": "location_sync",
            "actor": ACTOR,
            "device": PHONE,
            "ip": SYNTHETIC_IP,
            "object": "field session location context",
            "device_gps": DEVICE_GPS,
            "ip_location": IP_LOCATION,
        },
        {
            "timestamp": "2026-10-18T19:46:00Z",
            "action": "message_sent",
            "actor": ACTOR,
            "device": PHONE,
            "ip": SYNTHETIC_IP,
            "object": "Upload complete; archive is in the review vault.",
        },
    ]
    (CASE_DIR / "chat_export.json").write_text(
        json.dumps(chat, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    _write_csv(
        CASE_DIR / "browser_history.csv",
        ["timestamp", "action", "url", "actor", "device", "ip"],
        [[
            "2026-10-18T19:44:00Z",
            "upload",
            "https://vault.example.test/upload/CASE-001.tar.gz",
            ACTOR,
            LAPTOP,
            SYNTHETIC_IP,
        ]],
    )
    _write_csv(
        CASE_DIR / "system_log.csv",
        ["timestamp", "action", "actor", "device", "ip", "object"],
        [
            ["2026-10-18T02:17:00Z", "login", ACTOR, LAPTOP, SYNTHETIC_IP, "interactive session"],
            ["2026-10-18T19:41:00Z", "archive_created", ACTOR, LAPTOP, SYNTHETIC_IP, "CASE-001.tar.gz"],
        ],
    )

    dns_query = (
        IP(src=SYNTHETIC_IP, dst="203.0.113.53", id=101)
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname="vault.example.test"))
    )
    dns_answer = (
        IP(src="203.0.113.53", dst=SYNTHETIC_IP, id=102)
        / UDP(sport=53, dport=53000)
        / DNS(
            qr=1,
            qd=DNSQR(qname="vault.example.test"),
            an=DNSRR(rrname="vault.example.test", type="A", rdata="203.0.113.80"),
        )
    )
    dns_query.time = _epoch("2026-10-18T19:43:30Z")
    dns_answer.time = _epoch("2026-10-18T19:43:31Z")
    wrpcap(str(CASE_DIR / "network_dns.pcap"), [dns_query, dns_answer])

    _write_photo(
        CASE_DIR / "field_photo.jpg",
        "2026-10-18T02:24:00Z",
        PHOTO_GPS,
    )
    _write_photo(
        CASE_DIR / "reference_photo.jpg",
        "2026-10-18T02:25:00Z",
        None,
    )


if __name__ == "__main__":
    generate_case()