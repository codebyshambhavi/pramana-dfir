"""Stage 0 / T0: the pipeline fails explicitly. No adapter, no baseline findings."""
from __future__ import annotations

import io
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.services import pipeline


def test_adapters_are_gone():
    assert not hasattr(pipeline, "_analyze_adapter")
    assert not hasattr(pipeline, "_parse_evidence_adapter")


def test_missing_schema_raises_instead_of_inline_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline, "EVENT_SCHEMA_PATH", tmp_path / "absent.json")
    monkeypatch.setattr(pipeline, "_event_validator", None)
    with pytest.raises(pipeline.PipelineError, match="schema is missing"):
        pipeline.validate_event_dict({})


def test_analyzer_failure_propagates_and_is_not_replaced_by_a_baseline_finding(monkeypatch):
    import intelligence

    def boom(_events):
        raise RuntimeError("analyzer exploded")

    monkeypatch.setattr(intelligence, "analyze", boom)
    events = [{
        "event_id": "EV-1", "case_id": "C", "evidence_id": "EVID-001", "artifact_ref": "x#row=1",
        "sha256": "a" * 64, "timestamp": "2026-10-18T10:00:00Z", "source": "log", "action": "login",
    }]
    with pytest.raises(RuntimeError, match="analyzer exploded"):
        pipeline.execute_analyze(events, case_id="C")


def test_unsupported_evidence_is_rejected_and_nothing_is_stored(client: TestClient, db_session):
    from app.db.models import CustodyEntry, EventModel, Evidence
    from app.routers import evidence as evidence_router

    client.post("/cases", json={"name": "Reject", "case_id": "CASE-REJECT"})
    before = set(Path(evidence_router.UPLOAD_DIR).glob("*")) if Path(evidence_router.UPLOAD_DIR).exists() else set()

    res = client.post(
        "/cases/CASE-REJECT/evidence",
        files={"file": ("disk.img", io.BytesIO(b"raw-disk-bytes"), "application/octet-stream")},
    )
    assert res.status_code == 422
    assert "Unsupported evidence format" in res.json()["detail"]

    assert db_session.query(Evidence).count() == 0
    assert db_session.query(CustodyEntry).count() == 0
    assert db_session.query(EventModel).count() == 0
    after = set(Path(evidence_router.UPLOAD_DIR).glob("*")) if Path(evidence_router.UPLOAD_DIR).exists() else set()
    assert after == before, "rejected evidence must not leave an orphan file on disk"


def test_image_without_exif_timestamp_is_rejected_via_api(client: TestClient):
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (8, 8), "white").save(buf, format="JPEG")
    client.post("/cases", json={"name": "NoExif", "case_id": "CASE-NOEXIF"})
    res = client.post("/cases/CASE-NOEXIF/evidence", files={"file": ("p.jpg", io.BytesIO(buf.getvalue()), "image/jpeg")})
    assert res.status_code == 422
    assert "no usable EXIF timestamp" in res.json()["detail"]


def test_test_run_does_not_write_into_the_repo_tree():
    backend = Path(__file__).resolve().parents[1]
    assert not (backend / "data").exists()
    assert not (backend / "pramana.db").exists()
    assert "pramana-tests-" in os.environ["UPLOAD_DIR"]
