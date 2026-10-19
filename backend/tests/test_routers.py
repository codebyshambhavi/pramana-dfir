"""Additional targeted unit and integration tests for Pramana routers and services."""
from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.graph.builder import build_graph
from app.reports.lineage import get_finding_lineage
from app.services.pipeline import execute_analyze, validate_event_dict, validate_finding_dict


def test_schema_validators():
    """Verify that validator functions correctly validate compliant dictionaries."""
    sample_event = {
        "event_id": "EV-001",
        "case_id": "CASE-001",
        "evidence_id": "EVID-001",
        "artifact_ref": "chat.json#item=1",
        "sha256": "a" * 64,
        "timestamp": "2026-10-18T10:00:00Z",
        "source": "chat",
        "action": "message_sent",
    }
    # Should not raise
    validate_event_dict(sample_event)

    sample_finding = {
        "finding_id": "F-001",
        "case_id": "CASE-001",
        "type": "anomaly",
        "claim": "Suspicious login detected",
        "confidence": 0.85,
        "evidence_event_ids": ["EV-001"],
        "needs_human_review": True,
    }
    # Should not raise
    validate_finding_dict(sample_finding)


def test_location_contradiction_detection():
    """Verify that multiple conflicting geographic locations trigger contradiction finding."""
    events = [
        {
            "event_id": "EV-LOC-1",
            "case_id": "CASE-LOC",
            "evidence_id": "EVID-01",
            "artifact_ref": "photo.jpg#exif",
            "sha256": "b" * 64,
            "timestamp": "2026-10-18T12:00:00Z",
            "source": "image",
            "action": "photo_capture",
            "location": {"lat": 28.6139, "lon": 77.2090},  # Delhi
        },
        {
            "event_id": "EV-LOC-2",
            "case_id": "CASE-LOC",
            "evidence_id": "EVID-02",
            "artifact_ref": "auth.log#row=10",
            "sha256": "c" * 64,
            "timestamp": "2026-10-18T12:05:00Z",
            "source": "log",
            "action": "auth",
            "location": {"lat": 19.0760, "lon": 72.8777},  # Mumbai (conflicting)
        },
    ]
    findings = execute_analyze(events, case_id="CASE-LOC")
    types = [f["type"] for f in findings]
    assert "contradiction" in types


def test_graph_builder_edge_cases():
    """Verify graph builder handles empty lists, single nodes, and diverse entity types."""
    # Empty events
    empty_graph = build_graph([])
    assert empty_graph == {"nodes": [], "edges": []}

    # Complex multi-entity event
    event = {
        "event_id": "EV-G1",
        "actor": "alice",
        "device": "macbook_pro",
        "object": "passwords.kdbx",
        "ip": "10.0.0.5",
        "location": {"lat": 37.7749, "lon": -122.4194},
        "action": "accessed",
    }
    graph = build_graph([event])
    node_types = {n["type"] for n in graph["nodes"]}
    assert "person" in node_types
    assert "device" in node_types
    assert "file" in node_types
    assert "ip" in node_types
    assert "location" in node_types
    assert len(graph["edges"]) >= 3


def test_json_evidence_upload(client: TestClient):
    """Test ingestion and parsing of JSON evidence files."""
    case_id = "CASE-JSON-001"
    client.post("/cases", json={"name": "JSON Ingestion Case", "case_id": case_id})

    chat_data = [
        {
            "timestamp": "2026-10-18T14:00:00Z",
            "actor": "suspect_a",
            "action": "message_sent",
            "object": "Drop the file at midnight",
            "source": "chat",
        }
    ]
    json_bytes = json.dumps(chat_data).encode("utf-8")
    files = {"file": ("messages.json", io.BytesIO(json_bytes), "application/json")}
    res = client.post(f"/cases/{case_id}/evidence", files=files)
    assert res.status_code == 201
    assert res.json()["events_created"] >= 1

    # Verify event was stored with chat source
    res_events = client.get(f"/cases/{case_id}/events?source=chat")
    assert res_events.status_code == 200
    events = res_events.json()
    assert len(events) >= 1
    assert events[0]["source"] == "chat"
    assert events[0]["actor"] == "suspect_a"


def test_nonexistent_routes_and_entities(client: TestClient):
    """Verify appropriate 404 responses for invalid IDs across all endpoints."""
    assert client.get("/cases/DOES_NOT_EXIST/evidence").status_code == 404
    assert client.get("/cases/DOES_NOT_EXIST/events").status_code == 404
    assert client.get("/cases/DOES_NOT_EXIST/graph").status_code == 404
    assert client.post("/cases/DOES_NOT_EXIST/analyze").status_code == 404
    assert client.get("/cases/DOES_NOT_EXIST/findings").status_code == 404
    assert client.patch("/findings/DOES_NOT_EXIST", json={"status": "approved"}).status_code == 404
    assert client.get("/findings/DOES_NOT_EXIST/lineage").status_code == 404
    assert client.get("/cases/DOES_NOT_EXIST/report?format=pdf").status_code == 404
