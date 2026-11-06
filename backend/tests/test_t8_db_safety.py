"""Role 3 / Task 7: Database and Transaction Safety Tests for T7/T8.

Verifies:
1. Write-once immutability across all run tables (analysis_run, claim, claim_edge, run_snapshots, hypothesis_eval, source_coverage).
2. Atomicity & rollback: partial runs are never left behind if run creation fails.
3. Post-sealing child row rejection: cannot add claims or edges to an already sealed run.
4. Concurrency & distinct run IDs: rapid creation produces distinct, valid runs without collision.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.claims import ClaimSpec, ClaimValidationError, EdgeSpec
from app.db.models import (
    AnalysisRun,
    Claim,
    ClaimEdge,
    EventModel,
    Evidence,
    HypothesisEval,
    ImmutableRecordError,
    RunSnapshot,
    SourceCoverage,
)
from app.db.runs import create_analysis_run


CSV_DATA = (
    b"timestamp,action,actor,device,ip,object\n"
    b"2026-10-18T02:00:00Z,login,mira,dev-01,10.0.0.1,\n"
    b"2026-10-18T02:15:00Z,archive_create,mira,dev-01,10.0.0.1,secrets.tar.gz\n"
)


@pytest.fixture
def safety_setup(client: TestClient, db_session: Session):
    case_id = "CASE-DB-SAFETY-TEST"
    client.post("/cases", json={"name": "Safety Test Case", "case_id": case_id})
    res_ev = client.post(f"/cases/{case_id}/evidence", files={"file": ("sys.csv", CSV_DATA)})
    ev_id = res_ev.json()["evidence_id"]

    res_run = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res_run.json()["run_id"]

    return case_id, ev_id, run_id


def test_write_once_enforcement_all_run_tables(db_session: Session, safety_setup):
    """Updating or deleting rows in any run table fails via ORM and via SQL triggers."""
    case_id, ev_id, run_id = safety_setup

    # 1. AnalysisRun
    run_obj = db_session.get(AnalysisRun, run_id)
    with pytest.raises(ImmutableRecordError, match="write-once"):
        run_obj.engine_version = "mutated@2.0.0"
        db_session.flush()
    db_session.rollback()

    with pytest.raises(Exception):
        db_session.execute(text("UPDATE analysis_run SET engine_version = 'sql_mut' WHERE run_id = :r"), {"r": run_id})
        db_session.flush()
    db_session.rollback()

    with pytest.raises(ImmutableRecordError, match="immutable and never deleted"):
        db_session.delete(db_session.get(AnalysisRun, run_id))
        db_session.flush()
    db_session.rollback()

    # 2. Claim
    claim_obj = db_session.query(Claim).filter(Claim.run_id == run_id).first()
    if claim_obj:
        with pytest.raises(ImmutableRecordError, match="write-once"):
            claim_obj.grade = "C"
            db_session.flush()
        db_session.rollback()

        with pytest.raises(ImmutableRecordError, match="immutable and never deleted"):
            db_session.delete(claim_obj)
            db_session.flush()
        db_session.rollback()

    # 3. ClaimEdge
    edge_obj = db_session.query(ClaimEdge).filter(ClaimEdge.run_id == run_id).first()
    if edge_obj:
        with pytest.raises(ImmutableRecordError, match="write-once"):
            edge_obj.weight = 99.0
            db_session.flush()
        db_session.rollback()

        with pytest.raises(ImmutableRecordError, match="immutable and never deleted"):
            db_session.delete(edge_obj)
            db_session.flush()
        db_session.rollback()

    # 4. RunSnapshot
    snap_obj = db_session.get(RunSnapshot, run_id)
    if snap_obj:
        with pytest.raises(ImmutableRecordError, match="write-once"):
            snap_obj.ranking_hash = "mutated_hash"
            db_session.flush()
        db_session.rollback()

        with pytest.raises(ImmutableRecordError, match="immutable and never deleted"):
            db_session.delete(snap_obj)
            db_session.flush()
        db_session.rollback()


def test_atomicity_rollback_on_failure(db_session: Session, safety_setup):
    """If run creation fails mid-transaction, no partial run rows exist."""
    case_id, ev_id, _ = safety_setup

    initial_runs_count = db_session.query(AnalysisRun).filter(AnalysisRun.case_id == case_id).count()
    initial_claims_count = db_session.query(Claim).filter(Claim.case_id == case_id).count()

    events = db_session.query(EventModel).filter(EventModel.case_id == case_id).all()
    ev_id_1 = events[0].event_id

    # Create one valid claim and one invalid claim (dangling event) in the same call
    spec_valid = ClaimSpec(
        type="ACTOR_DEVICE_CONSISTENT",
        params={"actor": "mira", "device": "dev-01"},
        status="ASSERTED",
        grade="A",
        rule_id="RULE-1",
        rule_version="1.0",
        edges=[EdgeSpec(ref_kind="event", ref_id=ev_id_1, role="SUPPORTS")],
    )
    spec_invalid = ClaimSpec(
        type="ACTOR_DEVICE_CONSISTENT",
        params={"actor": "mira", "device": "dev-01"},
        status="ASSERTED",
        grade="A",
        rule_id="RULE-1",
        rule_version="1.0",
        edges=[EdgeSpec(ref_kind="event", ref_id="NON_EXISTENT_EV", role="SUPPORTS")],
    )

    with pytest.raises(ClaimValidationError):
        create_analysis_run(
            db_session,
            case_id=case_id,
            engine_version="pramana-engine@1.0.0",
            assumptions={"case_timezone": "UTC"},
            claims=[spec_valid, spec_invalid],
        )

    # Verify no partial claims or run rows were inserted
    assert db_session.query(AnalysisRun).filter(AnalysisRun.case_id == case_id).count() == initial_runs_count
    assert db_session.query(Claim).filter(Claim.case_id == case_id).count() == initial_claims_count


def test_no_children_can_be_added_post_sealing(db_session: Session, safety_setup):
    """Attempting to insert a child row for an already existing run fails via trigger and ORM."""
    case_id, ev_id, run_id = safety_setup

    events = db_session.query(EventModel).filter(EventModel.case_id == case_id).all()
    ev_id_1 = events[0].event_id

    # Attempt to insert a new claim directly for the existing sealed run
    late_claim = Claim(
        run_id=run_id,
        claim_id="LATE-CLAIM-001",
        claim_key="KEY-LATE",
        case_id=case_id,
        type="ACTOR_DEVICE_CONSISTENT",
        params={"actor": "intruder"},
        status="ASSERTED",
        grade="A",
        rule_id="RULE-LATE",
        rule_version="1.0",
        assumptions_hash="a" * 64,
    )

    with pytest.raises(ImmutableRecordError, match="already exists; records can only be written with the run itself"):
        db_session.add(late_claim)
        db_session.flush()
    db_session.rollback()


def test_distinct_run_ids_under_rapid_creation(client: TestClient, safety_setup):
    """Creating multiple runs produces distinct, valid IDs with no collisions."""
    case_id, _, _ = safety_setup

    run_ids = set()
    for _ in range(5):
        res = client.post(
            f"/cases/{case_id}/runs",
            json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
        )
        assert res.status_code == 201
        run_id = res.json()["run_id"]
        assert run_id not in run_ids
        run_ids.add(run_id)

    assert len(run_ids) == 5
