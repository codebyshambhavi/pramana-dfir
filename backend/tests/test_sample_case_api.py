"""Stage 0 acceptance through the real API + database: upload sample_case_001,
analyze, and check that all 3 planted ground-truth items come back as findings."""
from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from app.db.models import EventModel

CASE_DIR = Path(__file__).resolve().parents[2] / "datasets" / "sample_case_001"
FILES = [
    "system_log.csv", "browser_history.csv", "chat_export.json",
    "network_dns.pcap", "field_photo.jpg", "reference_photo.jpg",
]


def test_sample_case_001_through_api_exposes_all_three_planted_items(client: TestClient, db_session, monkeypatch):
    monkeypatch.setenv("PRAMANA_INTEL_TIMEZONE", "UTC")  # sample_case_001 is a UTC case
    monkeypatch.delenv("PRAMANA_SOURCE_CLOCKS", raising=False)
    assert client.post("/cases", json={"name": "Sample", "case_id": "CASE-001"}).status_code == 201
    for name in FILES:
        res = client.post("/cases/CASE-001/evidence", files={"file": (name, (CASE_DIR / name).read_bytes())})
        assert res.status_code == 201, (name, res.text)

    assert client.post("/cases/CASE-001/analyze").status_code == 200
    findings = client.get("/cases/CASE-001/findings").json()

    events = {e.event_id: e for e in db_session.query(EventModel).filter_by(case_id="CASE-001")}

    def original_name(event):
        # Over the API the parser sees the stored name "<case>_<6 hex>_<original>".
        return re.sub(r"^CASE-001_[0-9a-f]{6}_", "", event.artifact_ref.split("#")[0])

    def describe(finding):
        return {(events[i].source, events[i].action, original_name(events[i])) for i in finding["evidence_event_ids"]}

    anomaly = [f for f in findings if f["type"] == "anomaly" and ("log", "login", "system_log.csv") in describe(f)]
    correlation = [f for f in findings if f["type"] == "correlation"
                   and {("log", "archive_create", "system_log.csv"), ("browser", "file_upload", "browser_history.csv")} <= describe(f)]
    contradiction = [f for f in findings if f["type"] == "contradiction"
                     and {("image", "image_captured", "field_photo.jpg"), ("chat", "location_sync", "chat_export.json")} <= describe(f)]
    assert anomaly, "planted item 1 (odd-hour login) not detected"
    assert correlation, "planted item 2 (archive then upload) not detected"
    assert contradiction, "planted item 3 (photo location contradiction) not detected"

    # T2: the odd-hour rule fires only for the login, not for chat / photos / DNS.
    anomalies = [f for f in findings if f["type"] == "anomaly"]
    assert len(anomalies) == 1 and describe(anomalies[0]) == {("log", "login", "system_log.csv")}

    # The chat device GPS survived persistence into the database.
    chat_event = next(e for e in events.values() if e.action == "location_sync")
    assert chat_event.location == {"lat": 40.7128, "lon": -74.006}
