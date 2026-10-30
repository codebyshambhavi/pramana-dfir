"""Stage 0 acceptance: sample_case_001 exposes all 3 planted ground-truth items.

Runs the REAL evidence-engine parsers and the REAL intelligence pipeline on the
files in datasets/sample_case_001 (nothing is mocked or hard-coded) and checks
the findings against the event IDs written in GROUND_TRUTH.md itself, so the
document and the code cannot drift apart unnoticed.

Run from the repository root:  python3 -m pytest tests -q
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CASE_DIR = ROOT / "datasets" / "sample_case_001"
for entry in (ROOT / "evidence-engine", ROOT):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

import intelligence  # noqa: E402
from parsers import parse_evidence  # noqa: E402

EVIDENCE_FILES = [
    "system_log.csv", "browser_history.csv", "chat_export.json",
    "network_dns.pcap", "field_photo.jpg", "reference_photo.jpg",
]
ID_PATTERN = re.compile(r"`([0-9a-f]{12}:EV-\d{6})`")


def _ground_truth_items() -> list[dict]:
    """Parse GROUND_TRUTH.md into [{n, events:[ids], expected_type}] (no hard-coding)."""
    text = (CASE_DIR / "GROUND_TRUTH.md").read_text(encoding="utf-8")
    items = []
    for block in re.split(r"^## ", text, flags=re.M)[1:]:
        number = int(re.match(r"(\d+)\.", block).group(1))
        events_line = next(line for line in block.splitlines() if line.startswith("- Events:"))
        expected = re.search(r"Expected finding type:\s*(\w+)", block).group(1)
        items.append({"n": number, "events": ID_PATTERN.findall(events_line), "type": expected})
    return items


@pytest.fixture(autouse=True)
def _case_timezone_is_utc(monkeypatch):
    """sample_case_001 is a UTC case (its login is 02:17Z). Pin it so results never
    depend on the environment of whoever runs the tests."""
    monkeypatch.setenv("PRAMANA_INTEL_TIMEZONE", "UTC")
    monkeypatch.delenv("PRAMANA_SOURCE_CLOCKS", raising=False)


@pytest.fixture(scope="module")
def parsed():
    events = []
    for name in EVIDENCE_FILES:
        events += parse_evidence(str(CASE_DIR / name), "CASE-001")
    return events


@pytest.fixture
def findings(parsed):
    return intelligence.analyze(parsed)


def test_ground_truth_document_lists_three_items():
    items = _ground_truth_items()
    assert [i["n"] for i in items] == [1, 2, 3]
    assert [i["type"] for i in items] == ["anomaly", "correlation", "contradiction"]
    assert [len(i["events"]) for i in items] == [1, 2, 2]


def test_every_event_id_in_ground_truth_exists(parsed):
    """Guards against stale IDs in GROUND_TRUTH.md (one existed before Stage 0)."""
    known = {e["event_id"] for e in parsed}
    text = (CASE_DIR / "GROUND_TRUTH.md").read_text(encoding="utf-8")
    cited = set(ID_PATTERN.findall(text))
    assert cited, "GROUND_TRUTH.md cites no event IDs"
    assert cited <= known, f"stale IDs in GROUND_TRUTH.md: {sorted(cited - known)}"


@pytest.mark.parametrize("item", _ground_truth_items(), ids=lambda i: f"item{i['n']}-{i['type']}")
def test_planted_item_is_detected(item, findings):
    wanted = set(item["events"])
    matches = [
        f for f in findings
        if f["type"] == item["type"] and wanted <= set(f["evidence_event_ids"])
    ]
    assert matches, (
        f"planted item {item['n']} ({item['type']}) not detected; "
        f"findings: {[(f['type'], f['evidence_event_ids']) for f in findings]}"
    )
    for finding in matches:
        assert finding["needs_human_review"] is True
        assert finding["status"] == "pending"


def test_item2_is_the_archive_to_upload_rule(findings, parsed):
    by_id = {e["event_id"]: e for e in parsed}
    pair = [
        f for f in findings
        if f["type"] == "correlation"
        and {by_id[i]["action"] for i in f["evidence_event_ids"]} == {"archive_create", "file_upload"}
    ]
    assert len(pair) == 1


def test_item3_cites_the_photo_and_the_chat_device_gps(findings, parsed):
    by_id = {e["event_id"]: e for e in parsed}
    hits = [
        f for f in findings
        if f["type"] == "contradiction"
        and {by_id[i]["source"] for i in f["evidence_event_ids"]} == {"image", "chat"}
    ]
    assert len(hits) == 1
    chat = next(by_id[i] for i in hits[0]["evidence_event_ids"] if by_id[i]["source"] == "chat")
    assert chat["location"] == chat["raw"]["device_gps"]


def test_pipeline_is_deterministic(parsed):
    assert intelligence.analyze(parsed) == intelligence.analyze(list(reversed(parsed)))


# ---- Stage 0 / T2: odd-hour rule only fires for the genuine login ----------------
def test_only_the_login_is_an_odd_hour_anomaly(findings, parsed):
    """Before T2 the chat event and both photos were also flagged (UTC hour, every event)."""
    by_id = {e["event_id"]: e for e in parsed}
    anomalies = [f for f in findings if f["type"] == "anomaly"]
    assert len(anomalies) == 1
    (cited,) = anomalies[0]["evidence_event_ids"]
    assert (by_id[cited]["source"], by_id[cited]["action"]) == ("log", "login")


def test_under_ist_the_login_is_local_morning_so_it_is_not_flagged(monkeypatch, parsed):
    """02:17Z is 07:47 IST. The rule uses the case's local time, so no odd-hour anomaly.
    Items 2 (archive->upload) and 3 (location contradiction) are unaffected."""
    monkeypatch.setenv("PRAMANA_INTEL_TIMEZONE", "Asia/Kolkata")
    result = intelligence.analyze(parsed)
    assert [f for f in result if f["type"] == "anomaly"] == []
    assert any(f["type"] == "correlation" and "CASE-001.tar.gz" in f["claim"] for f in result)
    assert any(f["type"] == "contradiction" for f in result)


def test_source_clock_offset_is_honoured_without_changing_raw_timestamps(monkeypatch, parsed):
    """If the log clock ran 3 h ahead, the login really happened at 23:17Z the day before,
    which is outside the [00:00, 05:00) window, so the finding disappears. The raw event
    timestamp stays 02:17Z: the offset is applied when interpreting, never stored."""
    monkeypatch.setenv("PRAMANA_SOURCE_CLOCKS", '{"log": {"offset_seconds": 10800}}')
    result = intelligence.analyze(parsed)
    assert [f for f in result if f["type"] == "anomaly"] == []
    login = next(e for e in parsed if e["action"] == "login")
    assert login["timestamp"] == "2026-10-18T02:17:00Z"
