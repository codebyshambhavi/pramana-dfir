"""Role 3 / Task 3: Regression tests for historical run reproducibility and verification.

Verifies:
1. Historical run retrieval returns original results after events change.
2. Historical run retrieval returns original results after templates change.
3. Explicit verification passes when inputs are unchanged.
4. Explicit verification detects divergence when underlying data changed.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import AnalysisRun, EventModel
from app.services.runs import execute_analysis_run, get_run_details, verify_run_reproducibility
import intelligence.hyp.engine as hyp_engine


LOG_EVIDENCE = (
    b"timestamp,action,actor,device,ip,object\n"
    b"2026-10-18T02:00:00Z,login,mira,dev-01,10.0.0.1,\n"
    b"2026-10-18T02:15:00Z,archive_create,mira,dev-01,10.0.0.1,exfil.tar.gz\n"
)

BROWSER_EVIDENCE = (
    b"timestamp,action,url,actor,device,ip\n"
    b"2026-10-18T02:20:00Z,upload,https://vault.external/upload/exfil.tar.gz,mira,dev-01,10.0.0.1\n"
)


@pytest.fixture
def repro_setup(client: TestClient):
    case_id = "CASE-REPRODUCIBILITY-TEST"
    client.post("/cases", json={"name": "Reproducibility Test", "case_id": case_id})

    res_ev1 = client.post(f"/cases/{case_id}/evidence", files={"file": ("sys.csv", LOG_EVIDENCE)})
    res_ev2 = client.post(f"/cases/{case_id}/evidence", files={"file": ("browser.csv", BROWSER_EVIDENCE)})

    ev1_id = res_ev1.json()["evidence_id"]
    ev2_id = res_ev2.json()["evidence_id"]

    return case_id, ev1_id, ev2_id


def test_historical_retrieval_after_events_change(client: TestClient, db_session: Session, repro_setup):
    """Historical run results remain stable even if database events are subsequently altered."""
    case_id, ev1_id, ev2_id = repro_setup

    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    assert res.status_code == 201
    run_data = res.json()
    run_id = run_data["run_id"]
    original_ranking_hash = run_data["ranking_hash"]
    original_top_hyp = run_data["ranked_hypotheses"][0]["id"]
    original_reconstruction = run_data["reconstruction"]

    # Directly mutate an underlying event in database (simulating data drift or modification)
    ev = db_session.query(EventModel).filter(EventModel.case_id == case_id).first()
    assert ev is not None
    ev.action = "tampered_action"
    ev.actor = "someone_else"
    db_session.commit()

    # GET /runs/{run_id} MUST return the frozen historical result
    get_res = client.get(f"/runs/{run_id}")
    assert get_res.status_code == 200
    retrieved = get_res.json()

    assert retrieved["ranking_hash"] == original_ranking_hash
    assert retrieved["ranked_hypotheses"][0]["id"] == original_top_hyp
    assert retrieved["reconstruction"] == original_reconstruction
    # The run has a persisted ranking hash and template hash
    assert retrieved["template_hash"] is not None


def test_historical_retrieval_after_templates_change(client: TestClient, monkeypatch, repro_setup):
    """Historical run results remain stable even if hypothesis templates are altered."""
    case_id, _, _ = repro_setup

    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]
    original_top_hyp = res.json()["ranked_hypotheses"][0]["id"]
    original_ranking_hash = res.json()["ranking_hash"]

    # Mock load_templates to return a radically altered template list
    def mock_templates():
        from intelligence.hyp.engine import HypothesisTemplate
        return [
            HypothesisTemplate(
                id="H999",
                kind="fabricated",
                name="Fabricated Hypothesis",
                description="Should not affect historical run",
                stages=["dummy"],
                requires=[],
                expects=[],
                forbids=[],
                constraints=[],
            )
        ]

    monkeypatch.setattr(hyp_engine, "load_templates", mock_templates)

    # Historical run retrieval MUST return original historical conclusions (e.g. H1), NOT the altered templates!
    get_res = client.get(f"/runs/{run_id}")
    assert get_res.status_code == 200
    retrieved = get_res.json()
    assert retrieved["ranking_hash"] == original_ranking_hash
    assert retrieved["ranked_hypotheses"][0]["id"] == original_top_hyp


def test_explicit_verification_passes_when_inputs_unchanged(client: TestClient, repro_setup):
    """POST /runs/{id}/verify confirms match when data is unchanged."""
    case_id, _, _ = repro_setup

    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]

    # 1. Via GET /runs/{id}?verify=true
    get_res = client.get(f"/runs/{run_id}?verify=true")
    assert get_res.status_code == 200
    data = get_res.json()
    assert data["ranking_hash_verified"] is True
    assert "verification" in data
    assert data["verification"]["verified"] is True
    assert data["verification"]["diverged"] is False

    # 2. Via POST /runs/{id}/verify
    verify_res = client.post(f"/runs/{run_id}/verify")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["verified"] is True
    assert v_data["diverged"] is False
    assert v_data["recomputed_ranking_hash"] == v_data["persisted_ranking_hash"]


def test_explicit_verification_detects_divergence_when_data_changes(client: TestClient, db_session: Session, repro_setup):
    """POST /runs/{id}/verify detects divergence without mutating historical run."""
    case_id, _, _ = repro_setup

    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]

    # Mutate an event
    ev = db_session.query(EventModel).filter(EventModel.case_id == case_id).first()
    ev.timestamp = datetime(2026, 10, 18, 10, 0, 0)
    db_session.commit()

    # POST /runs/{id}/verify detects divergence
    verify_res = client.post(f"/runs/{run_id}/verify")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["verified"] is False
    assert v_data["diverged"] is True
    assert len(v_data["divergence_details"]) > 0

    # The historical run itself remains untouched
    get_res = client.get(f"/runs/{run_id}")
    assert get_res.status_code == 200
    assert get_res.json()["ranking_hash"] == res.json()["ranking_hash"]
