"""Zeek conn.log and dns.log parsers."""
from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from parsers.normalization import stable_event_id, utc_timestamp
from parsers.provenance import provenance_fields

PARSER_NAME = "zeek"
PARSER_VERSION = "1.0.0"


def _split_header(path: str) -> tuple[list[str], list[dict[str, str]], str]:
    rows: list[dict[str, str]] = []
    fields: list[str] = []
    separator = "\t"
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        lines = handle.readlines()
    for line in lines:
        if line.startswith("#fields"):
            fields = line.rstrip("\r\n").split(separator)[1:]
        elif line and not line.startswith("#"):
            values = line.rstrip("\r\n").split(separator)
            if fields:
                rows.append(dict(zip(fields, values)))
    if not fields:
        raise ValueError("Invalid Zeek log: missing #fields header")
    return fields, rows, separator


def parse(path: str, case_id: str, evidence_id: str, sha256: str) -> list[dict[str, Any]]:
    fields, rows, _ = _split_header(path)
    filename = Path(path).name
    dns_fields = {"uid", "ts", "query", "qtype_name", "answers", "rcode_name"}
    conn_fields = {"uid", "ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto"}
    kind = "dns" if dns_fields.issubset(set(fields)) else "conn" if conn_fields.issubset(set(fields)) else None
    if kind is None:
        raise ValueError("Unsupported Zeek log: expected conn.log or dns.log #fields")

    events: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        if row.get("ts") in (None, "-", ""):
            continue
        try:
            epoch = float(row["ts"])
            timestamp, assumption = utc_timestamp(datetime.fromtimestamp(epoch, tz=timezone.utc))
        except (ValueError, OverflowError) as exc:
            raise ValueError(f"Invalid Zeek timestamp at record {index}: {exc}") from exc

        locator = f"{filename}#{kind}=record-{index}"
        if kind == "conn":
            src = None if row.get("id.orig_h") == "-" else row.get("id.orig_h")
            dst = None if row.get("id.resp_h") == "-" else row.get("id.resp_h")
            action = "NETWORK_CONNECTION"
            object_value = f"{src}:{row.get('id.orig_p','-')}->{dst}:{row.get('id.resp_p','-')}"
            family = "network_connection"
        else:
            src = None
            dst = None
            action = "DNS_QUERY"
            query = None if row.get("query") == "-" else row.get("query")
            object_value = query
            family = "dns_log"

        event = {
            "event_id": stable_event_id("EV-ZEEK", case_id, evidence_id, locator),
            "case_id": case_id,
            "evidence_id": evidence_id,
            "artifact_ref": locator,
            "sha256": sha256,
            "timestamp": timestamp,
            "source": "zeek",
            "action": action,
            "raw": row,
            **provenance_fields(parser=PARSER_NAME, version=PARSER_VERSION, family=family, tz_assumption="epoch_utc" if assumption == "explicit_offset" else assumption),
        }
        if kind == "conn" and src:
            event["actor"] = src
            event["ip"] = src
        if object_value:
            event["object"] = object_value
        events.append(event)
    return events
