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

from app.db.models import AnalysisRun, EventModel, RunSnapshot
from app.services.runs import (
    execute_analysis_run,
    get_run_details,
    verify_run_reproducibility,
    detect_event_drift,
    canonical_event,
    CANONICAL_EVENT_FIELDS,
)
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

    # Historical replay succeeds from preserved original inputs,
    # cleanly distinguished from current database state comparison!
    replay = v_data["historical_replay"]
    assert replay["verified"] is True
    assert replay["replay_possible"] is True
    assert replay["ranking_hash_match"] is True
    assert replay["ranking_order_match"] is True
    assert replay["h0_residual_match"] is True
    assert replay["hypotheses_match"] is True
    assert replay["reconstruction_match"] is True
    assert replay["snapshot_authoritative"] is True

    curr = v_data["current_state_comparison"]
    assert curr["diverged"] is True
    assert curr["events_identical"] is False


def test_snapshot_preserves_event_inputs_and_template_contents(client: TestClient, db_session: Session, repro_setup):
    """Immutable snapshot preserves original event inputs and template contents, not just template_hash."""
    from app.db.models import RunSnapshot

    case_id, _, _ = repro_setup
    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]

    snap = db_session.get(RunSnapshot, run_id)
    assert snap is not None
    assert "events" in snap.snapshot
    assert len(snap.snapshot["events"]) >= 3
    # Check that events have required fields
    ev0 = snap.snapshot["events"][0]
    assert "event_id" in ev0
    assert "timestamp" in ev0
    assert "action" in ev0

    assert "templates" in snap.snapshot
    assert len(snap.snapshot["templates"]) == 3
    t_ids = {t["id"] for t in snap.snapshot["templates"]}
    assert t_ids == {"H1", "H2", "H3"}
    # Verify template content contains full stage, requirement, and constraint definitions
    h1 = next(t for t in snap.snapshot["templates"] if t["id"] == "H1")
    assert "stages" in h1
    assert "requires" in h1
    assert "expects" in h1
    assert "forbids" in h1
    assert "constraints" in h1


def test_authoritative_database_snapshot_source(client: TestClient, repro_setup):
    """Database snapshot is authoritative and returned as authoritative source."""
    case_id, _, _ = repro_setup
    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]

    get_res = client.get(f"/runs/{run_id}")
    assert get_res.status_code == 200
    data = get_res.json()
    assert data["snapshot_source"] == "database"
    assert data["snapshot_authoritative"] is True
    assert data["snapshot_status"] == "AUTHORITATIVE_DB"
    assert "snapshot_warning" not in data


def test_filesystem_fallback_marked_non_durable(client: TestClient, db_session: Session, repro_setup):
    """Local filesystem fallback cannot be presented as durable production storage."""
    from app.db.models import RunSnapshot

    case_id, _, _ = repro_setup
    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]

    # Delete the DB snapshot row directly in SQL (bypassing ORM trigger for test simulation)
    from sqlalchemy import text
    db_session.execute(text("PRAGMA foreign_keys=OFF"))
    db_session.execute(text("DROP TRIGGER IF EXISTS trg_run_snapshots_no_delete"))
    db_session.execute(text("DELETE FROM run_snapshots WHERE run_id = :r"), {"r": run_id})
    db_session.commit()
    db_session.execute(text("PRAGMA foreign_keys=ON"))

    # When retrieved, filesystem fallback exists on disk
    get_res = client.get(f"/runs/{run_id}")
    assert get_res.status_code == 200
    data = get_res.json()
    assert data["snapshot_source"] == "local_cache"
    assert data["snapshot_authoritative"] is False
    assert data["snapshot_status"] == "EPHEMERAL_LOCAL_FALLBACK"
    assert "snapshot_warning" in data
    assert "non-authoritative" in data["snapshot_warning"]


def test_snapshot_unavailable_behavior(client: TestClient, db_session: Session, repro_setup):
    """When both database snapshot and disk cache are missing, returns UNAVAILABLE without fabricating results."""
    case_id, _, _ = repro_setup
    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]

    # Remove DB snapshot
    from sqlalchemy import text
    db_session.execute(text("PRAGMA foreign_keys=OFF"))
    db_session.execute(text("DROP TRIGGER IF EXISTS trg_run_snapshots_no_delete"))
    db_session.execute(text("DELETE FROM run_snapshots WHERE run_id = :r"), {"r": run_id})
    db_session.commit()
    db_session.execute(text("PRAGMA foreign_keys=ON"))

    # Remove disk cache
    disk_file = Path(f"storage/runs/{run_id}.json")
    if disk_file.exists():
        disk_file.unlink()

    get_res = client.get(f"/runs/{run_id}")
    assert get_res.status_code == 200
    data = get_res.json()
    assert data["snapshot_status"] == "UNAVAILABLE"
    assert data["snapshot_authoritative"] is False
    assert data["ranked_hypotheses"] == []
    assert data["reconstruction"] is None
    assert data["ranking_hash_verified"] is False
    assert "snapshot_warning" in data

    # Verify endpoint also indicates replay impossible
    verify_res = client.post(f"/runs/{run_id}/verify")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["historical_replay"]["replay_possible"] is False
    assert v_data["historical_replay"]["status"] == "UNAVAILABLE"


# -------------------------------------------------------------------------
# Phase 3 Hardening: Regression tests for Reviewer Deliverables 3, 4, 5, 6
# -------------------------------------------------------------------------


def test_replay_uses_preserved_template_version_a_when_disk_has_version_b(
    client: TestClient, monkeypatch, repro_setup
):
    """Historical replay uses the preserved templates stored in the run snapshot,
    not altered active disk templates (Version B).
    """
    case_id, _, _ = repro_setup
    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]
    original_ranking_hash = res.json()["ranking_hash"]

    # Mock disk templates to simulate template Version B
    from intelligence.hyp.engine import HypothesisTemplate

    def mock_version_b_templates():
        return [
            HypothesisTemplate(
                id="H_VERSION_B",
                kind="altered",
                name="Version B Template",
                description="Altered template that would change ranking",
                stages=["stage_x"],
                requires=[],
                expects=[],
                forbids=[],
                constraints=[],
            )
        ]

    monkeypatch.setattr(hyp_engine, "load_templates", mock_version_b_templates)

    # Verify run reproducibility:
    # 1. Historical replay MUST use Version A preserved in snapshot -> VERIFIED
    verify_res = client.post(f"/runs/{run_id}/verify")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["historical_replay"]["replay_possible"] is True
    assert v_data["historical_replay"]["status"] == "VERIFIED"
    assert v_data["historical_replay"]["ranking_hash_match"] is True
    assert v_data["historical_replay"]["verified"] is True

    # 2. Current state comparison MUST detect divergence because disk templates != Version A
    assert v_data["current_state_comparison"]["templates_identical"] is False
    assert v_data["current_state_comparison"]["diverged"] is True
    assert v_data["diverged"] is True


def test_replay_unavailable_when_snapshot_lacks_preserved_templates(
    client: TestClient, db_session: Session, repro_setup
):
    """Missing preserved templates in snapshot must produce an explicit UNAVAILABLE result,
    never silently substituting current disk templates.
    """
    from sqlalchemy import text

    case_id, _, _ = repro_setup
    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]

    # Strip 'templates' from DB snapshot
    snap = db_session.get(RunSnapshot, run_id)
    assert snap is not None
    tampered = dict(snap.snapshot)
    tampered.pop("templates", None)

    db_session.execute(text("PRAGMA foreign_keys=OFF"))
    db_session.execute(text("DROP TRIGGER IF EXISTS trg_run_snapshots_no_update"))
    db_session.execute(
        text("UPDATE run_snapshots SET snapshot = :s WHERE run_id = :r"),
        {"s": json.dumps(tampered), "r": run_id},
    )
    db_session.commit()
    db_session.execute(text("PRAGMA foreign_keys=ON"))
    db_session.expire_all()

    # Also update disk cache file if present
    disk_file = Path(f"storage/runs/{run_id}.json")
    if disk_file.exists():
        disk_file.write_text(json.dumps(tampered), encoding="utf-8")

    verify_res = client.post(f"/runs/{run_id}/verify")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["historical_replay"]["replay_possible"] is False
    assert v_data["historical_replay"]["status"] == "UNAVAILABLE"
    assert v_data["historical_replay"]["verified"] is False
    assert any("preserved templates missing" in d for d in v_data["historical_replay"]["discrepancies"])


def test_replay_fails_on_stage_time_window_mutation(
    client: TestClient, db_session: Session, repro_setup
):
    """Deliberate mutation of a stage time window in historical snapshot must fail replay verification."""
    from sqlalchemy import text

    case_id, _, _ = repro_setup
    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]

    snap = db_session.get(RunSnapshot, run_id)
    tampered = json.loads(json.dumps(snap.snapshot))
    recon = tampered.get("reconstruction")
    assert recon is not None and len(recon["stages"]) > 0

    # Mutate time window boundary
    recon["stages"][0]["time_window"] = {
        "lo": "1999-01-01T00:00:00Z",
        "hi": "1999-01-01T01:00:00Z",
    }

    db_session.execute(text("PRAGMA foreign_keys=OFF"))
    db_session.execute(text("DROP TRIGGER IF EXISTS trg_run_snapshots_no_update"))
    db_session.execute(
        text("UPDATE run_snapshots SET snapshot = :s WHERE run_id = :r"),
        {"s": json.dumps(tampered), "r": run_id},
    )
    db_session.commit()
    db_session.execute(text("PRAGMA foreign_keys=ON"))
    db_session.expire_all()

    disk_file = Path(f"storage/runs/{run_id}.json")
    if disk_file.exists():
        disk_file.write_text(json.dumps(tampered), encoding="utf-8")

    verify_res = client.post(f"/runs/{run_id}/verify")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["historical_replay"]["reconstruction_match"] is False
    assert v_data["historical_replay"]["verified"] is False
    assert any("time window" in d for d in v_data["historical_replay"]["discrepancies"])


def test_replay_fails_on_temporal_relationship_mutation(
    client: TestClient, db_session: Session, repro_setup
):
    """Deliberate mutation of a temporal relationship between stages must fail replay verification."""
    from sqlalchemy import text

    case_id, _, _ = repro_setup
    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]

    snap = db_session.get(RunSnapshot, run_id)
    tampered = json.loads(json.dumps(snap.snapshot))
    recon = tampered.get("reconstruction")
    assert recon is not None and len(recon["stages"]) >= 2

    # Mutate stage 1 temporal relationship
    recon["stages"][1]["relationship_to_previous"] = "OUT_OF_ORDER"

    db_session.execute(text("PRAGMA foreign_keys=OFF"))
    db_session.execute(text("DROP TRIGGER IF EXISTS trg_run_snapshots_no_update"))
    db_session.execute(
        text("UPDATE run_snapshots SET snapshot = :s WHERE run_id = :r"),
        {"s": json.dumps(tampered), "r": run_id},
    )
    db_session.commit()
    db_session.execute(text("PRAGMA foreign_keys=ON"))
    db_session.expire_all()

    disk_file = Path(f"storage/runs/{run_id}.json")
    if disk_file.exists():
        disk_file.write_text(json.dumps(tampered), encoding="utf-8")

    verify_res = client.post(f"/runs/{run_id}/verify")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["historical_replay"]["reconstruction_match"] is False
    assert v_data["historical_replay"]["verified"] is False
    assert any("relationship" in d for d in v_data["historical_replay"]["discrepancies"])


def test_replay_fails_on_event_assignment_mutation(
    client: TestClient, db_session: Session, repro_setup
):
    """Deliberate mutation of event assignments to a stage must fail replay verification."""
    from sqlalchemy import text

    case_id, _, _ = repro_setup
    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]

    snap = db_session.get(RunSnapshot, run_id)
    tampered = json.loads(json.dumps(snap.snapshot))
    recon = tampered.get("reconstruction")
    assert recon is not None and len(recon["stages"]) > 0

    # Mutate raw_events in stage 0
    recon["stages"][0]["raw_events"] = [{"event_id": "TAMPERED_EVENT_ASSIGNMENT"}]

    db_session.execute(text("PRAGMA foreign_keys=OFF"))
    db_session.execute(text("DROP TRIGGER IF EXISTS trg_run_snapshots_no_update"))
    db_session.execute(
        text("UPDATE run_snapshots SET snapshot = :s WHERE run_id = :r"),
        {"s": json.dumps(tampered), "r": run_id},
    )
    db_session.commit()
    db_session.execute(text("PRAGMA foreign_keys=ON"))
    db_session.expire_all()

    disk_file = Path(f"storage/runs/{run_id}.json")
    if disk_file.exists():
        disk_file.write_text(json.dumps(tampered), encoding="utf-8")

    verify_res = client.post(f"/runs/{run_id}/verify")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["historical_replay"]["reconstruction_match"] is False
    assert v_data["historical_replay"]["verified"] is False
    assert any("raw_events differ" in d for d in v_data["historical_replay"]["discrepancies"])


def test_replay_fails_on_residual_h0_mutation(
    client: TestClient, db_session: Session, repro_setup
):
    """Deliberate mutation of H0 residual unassigned events must fail replay verification."""
    from sqlalchemy import text

    case_id, _, _ = repro_setup
    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]

    snap = db_session.get(RunSnapshot, run_id)
    tampered = json.loads(json.dumps(snap.snapshot))
    h0 = tampered.get("h0_residual")
    assert h0 is not None

    # Mutate H0 unassigned events
    h0["unassigned_event_ids"] = ["EVENT-EXTRA-UNASSIGNED-999"]
    h0["unassigned_event_count"] = 1

    db_session.execute(text("PRAGMA foreign_keys=OFF"))
    db_session.execute(text("DROP TRIGGER IF EXISTS trg_run_snapshots_no_update"))
    db_session.execute(
        text("UPDATE run_snapshots SET snapshot = :s WHERE run_id = :r"),
        {"s": json.dumps(tampered), "r": run_id},
    )
    db_session.commit()
    db_session.execute(text("PRAGMA foreign_keys=ON"))
    db_session.expire_all()

    disk_file = Path(f"storage/runs/{run_id}.json")
    if disk_file.exists():
        disk_file.write_text(json.dumps(tampered), encoding="utf-8")

    verify_res = client.post(f"/runs/{run_id}/verify")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["historical_replay"]["h0_residual_match"] is False
    assert v_data["historical_replay"]["verified"] is False
    assert any("H0 unassigned events" in d for d in v_data["historical_replay"]["discrepancies"])


def test_replay_fails_on_individual_item_evaluation_mutation(
    client: TestClient, db_session: Session, repro_setup
):
    """Deliberate mutation of an individual item evaluation state must fail replay verification."""
    from sqlalchemy import text

    case_id, _, _ = repro_setup
    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]

    snap = db_session.get(RunSnapshot, run_id)
    tampered = json.loads(json.dumps(snap.snapshot))
    hyps = tampered.get("ranked_hypotheses", [])
    assert len(hyps) > 0 and len(hyps[0].get("evaluations", [])) > 0

    # Mutate evaluation state of first item
    item_eval = hyps[0]["evaluations"][0]
    original_state = item_eval["state"]
    item_eval["state"] = "VIOLATED" if original_state != "VIOLATED" else "SATISFIED"

    db_session.execute(text("PRAGMA foreign_keys=OFF"))
    db_session.execute(text("DROP TRIGGER IF EXISTS trg_run_snapshots_no_update"))
    db_session.execute(
        text("UPDATE run_snapshots SET snapshot = :s WHERE run_id = :r"),
        {"s": json.dumps(tampered), "r": run_id},
    )
    db_session.commit()
    db_session.execute(text("PRAGMA foreign_keys=ON"))
    db_session.expire_all()

    disk_file = Path(f"storage/runs/{run_id}.json")
    if disk_file.exists():
        disk_file.write_text(json.dumps(tampered), encoding="utf-8")

    verify_res = client.post(f"/runs/{run_id}/verify")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["historical_replay"]["hypotheses_match"] is False
    assert v_data["historical_replay"]["verified"] is False
    assert any("state" in d for d in v_data["historical_replay"]["discrepancies"])


def test_replay_fails_on_hypothesis_score_mutation(
    client: TestClient, db_session: Session, repro_setup
):
    """Deliberate mutation of hypothesis inconsistency score must fail replay verification."""
    from sqlalchemy import text

    case_id, _, _ = repro_setup
    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]

    snap = db_session.get(RunSnapshot, run_id)
    tampered = json.loads(json.dumps(snap.snapshot))
    hyps = tampered.get("ranked_hypotheses", [])
    assert len(hyps) > 0

    # Mutate inconsistency score
    hyps[0]["inconsistency_score"] = 999.99

    db_session.execute(text("PRAGMA foreign_keys=OFF"))
    db_session.execute(text("DROP TRIGGER IF EXISTS trg_run_snapshots_no_update"))
    db_session.execute(
        text("UPDATE run_snapshots SET snapshot = :s WHERE run_id = :r"),
        {"s": json.dumps(tampered), "r": run_id},
    )
    db_session.commit()
    db_session.execute(text("PRAGMA foreign_keys=ON"))
    db_session.expire_all()

    disk_file = Path(f"storage/runs/{run_id}.json")
    if disk_file.exists():
        disk_file.write_text(json.dumps(tampered), encoding="utf-8")

    verify_res = client.post(f"/runs/{run_id}/verify")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["historical_replay"]["hypotheses_match"] is False
    assert v_data["historical_replay"]["verified"] is False
    assert any("inconsistency score" in d for d in v_data["historical_replay"]["discrepancies"])


def test_snapshot_availability_vs_ranking_verification(
    client: TestClient, db_session: Session, repro_setup
):
    """Snapshot availability is distinct from ranking hash verification."""
    from sqlalchemy import text

    case_id, _, _ = repro_setup
    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]

    # 1. Normal retrieval: snapshot is available, authoritative DB, and replay verification succeeds
    det = client.get(f"/runs/{run_id}").json()
    assert det["snapshot_available"] is True
    assert det["snapshot_authoritative"] is True
    assert det["snapshot_status"] == "AUTHORITATIVE_DB"
    assert det["ranking_hash_verified"] is True

    # 2. Tampered snapshot ranking data: snapshot is available, but ranking_hash_verified must be FALSE
    snap = db_session.get(RunSnapshot, run_id)
    tampered = json.loads(json.dumps(snap.snapshot))
    # Mutate ranked hypotheses so replay produces divergent hash
    tampered["events"][0]["action"] = "tampered_action_for_replay"

    db_session.execute(text("PRAGMA foreign_keys=OFF"))
    db_session.execute(text("DROP TRIGGER IF EXISTS trg_run_snapshots_no_update"))
    db_session.execute(
        text("UPDATE run_snapshots SET snapshot = :s WHERE run_id = :r"),
        {"s": json.dumps(tampered), "r": run_id},
    )
    db_session.commit()
    db_session.execute(text("PRAGMA foreign_keys=ON"))
    db_session.expire_all()

    disk_file = Path(f"storage/runs/{run_id}.json")
    if disk_file.exists():
        disk_file.write_text(json.dumps(tampered), encoding="utf-8")

    tampered_det = client.get(f"/runs/{run_id}").json()
    assert tampered_det["snapshot_available"] is True
    assert tampered_det["snapshot_authoritative"] is True
    # Crucial: snapshot is present, but ranking_hash_verified must be FALSE because replay diverged!
    assert tampered_det["ranking_hash_verified"] is False

    # 3. Missing replay inputs: snapshot available, but events stripped -> ranking_hash_verified is FALSE
    tampered.pop("events", None)
    db_session.execute(text("PRAGMA foreign_keys=OFF"))
    db_session.execute(text("DROP TRIGGER IF EXISTS trg_run_snapshots_no_update"))
    db_session.execute(
        text("UPDATE run_snapshots SET snapshot = :s WHERE run_id = :r"),
        {"s": json.dumps(tampered), "r": run_id},
    )
    db_session.commit()
    db_session.execute(text("PRAGMA foreign_keys=ON"))
    db_session.expire_all()
    if disk_file.exists():
        disk_file.write_text(json.dumps(tampered), encoding="utf-8")

    no_events_det = client.get(f"/runs/{run_id}").json()
    assert no_events_det["snapshot_available"] is True
    assert no_events_det["ranking_hash_verified"] is False


@pytest.mark.parametrize(
    "field,mutated_val",
    [
        ("event_id", "EVENT-MUTATED-999"),
        ("case_id", "CASE-MUTATED-999"),
        ("evidence_id", "EVID-MUTATED-999"),
        ("artifact_ref", "/mutated/path/sys.log:999"),
        ("sha256", "0000000000000000000000000000000000000000000000000000000000000000"),
        ("timestamp", "2026-10-18T05:55:55Z"),
        ("source", "mutated_source"),
        ("family", "mutated_family"),
        ("device", "mutated_device"),
        ("actor", "mutated_actor"),
        ("action", "mutated_action"),
        ("object", "mutated_object"),
        ("ip", "192.168.1.99"),
        ("location", {"lat": 12.3456, "lon": 78.9101}),
        ("raw", {"mutated": True, "key": "value"}),
    ],
)
def test_canonical_event_drift_detection_parameterized(field: str, mutated_val: Any):
    """Detect event drift independently across every canonical event field."""
    base_event = {
        "event_id": "EV-100",
        "case_id": "CASE-1",
        "evidence_id": "EVID-1",
        "artifact_ref": "/var/log/audit.log:10",
        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "timestamp": "2026-10-18T02:00:00Z",
        "source": "log",
        "family": "auth",
        "device": "workstation-01",
        "actor": "alice",
        "action": "login",
        "object": "system",
        "ip": "10.0.0.5",
        "location": {"lat": 37.7749, "lon": -122.4194},
        "raw": {"pid": 1234, "cmd": "login"},
    }

    orig_events = [base_event]
    mutated_event = dict(base_event)
    mutated_event[field] = mutated_val
    current_events = [mutated_event]

    events_identical, drift_details = detect_event_drift(orig_events, current_events)
    assert events_identical is False
    assert len(drift_details) > 0

    if field == "event_id":
        assert any(d["type"] == "EVENT_REMOVED" and d["event_id"] == "EV-100" for d in drift_details)
        assert any(d["type"] == "EVENT_ADDED" and d["event_id"] == "EVENT-MUTATED-999" for d in drift_details)
    else:
        assert any(
            d["type"] == "FIELD_MUTATED" and d["field"] == field for d in drift_details
        )


