"""T3: schema additions, Event v1.1 persistence, run immutability and evidence non-deletion."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect

from app.db.models import (
    EVIDENCE_QUARANTINED,
    AnalysisRun,
    Case,
    Claim,
    ClaimEdge,
    CustodyEntry,
    EventModel,
    Evidence,
    HypothesisEval,
    ImmutableRecordError,
    SourceCoverage,
)
from app.db.runs import create_analysis_run, finalize_run, snapshot_digest

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_DIR = REPO_ROOT / "datasets" / "sample_case_001"
EVENT_SCHEMA = json.loads((REPO_ROOT / "contracts" / "event.schema.json").read_text(encoding="utf-8"))

LOG_CSV = b"timestamp,action,user,host\n2026-10-18T02:17:00Z,login,alice,LAPTOP-1\n"


def _upload(client: TestClient, case_id: str, name: str = "system_log.csv", content: bytes = LOG_CSV) -> dict:
    res = client.post(f"/cases/{case_id}/evidence", files={"file": (name, content)})
    assert res.status_code == 201, res.text
    return res.json()


def _case(client: TestClient, case_id: str = "CASE-T3") -> str:
    assert client.post("/cases", json={"name": "T3", "case_id": case_id}).status_code == 201
    return case_id


# --- schema -------------------------------------------------------------------

EXPECTED_COLUMNS = {
    "analysis_run": {"run_id", "case_id", "status", "created_at", "completed_at", "engine_version",
                     "config", "evidence_snapshot", "input_digest", "error"},
    "claim": {"claim_id", "run_id", "case_id", "kind", "statement", "confidence", "event_ids",
              "evidence_ids", "rule_id", "details", "needs_human_review", "created_at"},
    "claim_edge": {"id", "run_id", "src_claim_id", "dst_claim_id", "relation", "weight", "details"},
    "hypothesis_eval": {"id", "run_id", "hypothesis_claim_id", "verdict", "score", "supporting_claim_ids",
                        "contradicting_claim_ids", "missing_evidence", "details", "created_at"},
    "source_coverage": {"id", "run_id", "evidence_id", "source", "family", "included", "reason",
                        "event_count", "time_start", "time_end", "details"},
}


@pytest.mark.parametrize("table", sorted(EXPECTED_COLUMNS))
def test_t3_tables_exist_with_columns(table, db_session):
    insp = inspect(db_session.get_bind())
    assert table in insp.get_table_names()
    assert {c["name"] for c in insp.get_columns(table)} == EXPECTED_COLUMNS[table]


def test_t3_foreign_keys(db_session):
    insp = inspect(db_session.get_bind())
    fks = {t: {(fk["constrained_columns"][0], fk["referred_table"]) for fk in insp.get_foreign_keys(t)}
           for t in EXPECTED_COLUMNS}
    assert ("case_id", "cases") in fks["analysis_run"]
    assert {("run_id", "analysis_run"), ("case_id", "cases")} <= fks["claim"]
    assert {("run_id", "analysis_run"), ("src_claim_id", "claim"), ("dst_claim_id", "claim")} <= fks["claim_edge"]
    assert {("run_id", "analysis_run"), ("hypothesis_claim_id", "claim")} <= fks["hypothesis_eval"]
    assert {("run_id", "analysis_run"), ("evidence_id", "evidence")} <= fks["source_coverage"]


def test_evidence_and_event_new_columns(db_session):
    insp = inspect(db_session.get_bind())
    assert {"status", "verified_at"} <= {c["name"] for c in insp.get_columns("evidence")}
    assert {"parser_version", "tz_assumption", "family"} <= {c["name"] for c in insp.get_columns("events")}


# --- evidence defaults and Event v1.1 persistence -----------------------------

def test_new_evidence_is_active_and_unverified(client, db_session):
    case_id = _case(client)
    evidence_id = _upload(client, case_id)["evidence_id"]
    ev = db_session.get(Evidence, evidence_id)
    assert ev.status == "ACTIVE"
    assert ev.verified_at is None
    listed = client.get(f"/cases/{case_id}/evidence").json()[0]
    assert listed["status"] == "ACTIVE"
    assert listed["verified_at"] is None


def test_event_v11_fields_are_persisted_and_served(client, db_session):
    case_id = _case(client)
    for name in ("system_log.csv", "browser_history.csv", "chat_export.json"):
        _upload(client, case_id, name, (SAMPLE_DIR / name).read_bytes())

    rows = db_session.query(EventModel).filter_by(case_id=case_id).all()
    assert rows
    for row in rows:
        assert row.parser_version and "@" in row.parser_version
        assert row.tz_assumption
        assert row.family
    assert {r.family for r in rows} >= {"system_log", "browser_history", "chat_export"}

    served = client.get(f"/cases/{case_id}/events").json()
    assert len(served) == len(rows)
    for event in served:
        assert {"parser_version", "tz_assumption", "family"} <= event.keys()
        jsonschema.validate(event, EVENT_SCHEMA)


def test_legacy_event_without_v11_fields_still_serializes(client, db_session):
    case_id = _case(client)
    _upload(client, case_id)
    row = db_session.query(EventModel).filter_by(case_id=case_id).first()
    row.parser_version = row.tz_assumption = row.family = None
    db_session.commit()
    data = row.to_dict()
    assert not {"parser_version", "tz_assumption", "family"} & data.keys()
    jsonschema.validate(data, EVENT_SCHEMA)


# --- evidence is never deleted; intake hash never changes ---------------------

def test_evidence_row_cannot_be_deleted(client, db_session):
    case_id = _case(client)
    evidence_id = _upload(client, case_id)["evidence_id"]
    db_session.delete(db_session.get(Evidence, evidence_id))
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()
    assert db_session.get(Evidence, evidence_id) is not None


def test_custody_entry_cannot_be_deleted(client, db_session):
    case_id = _case(client)
    evidence_id = _upload(client, case_id)["evidence_id"]
    entry = db_session.query(CustodyEntry).filter_by(evidence_id=evidence_id).first()
    db_session.delete(entry)
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()
    assert db_session.query(CustodyEntry).filter_by(evidence_id=evidence_id).count() == 1


def test_deleting_case_does_not_cascade_to_evidence(client, db_session):
    case_id = _case(client)
    evidence_id = _upload(client, case_id)["evidence_id"]
    db_session.delete(db_session.get(Case, case_id))
    with pytest.raises(Exception):
        db_session.flush()
    db_session.rollback()
    assert db_session.get(Evidence, evidence_id) is not None


def test_intake_sha256_is_immutable(client, db_session):
    case_id = _case(client)
    evidence_id = _upload(client, case_id)["evidence_id"]
    ev = db_session.get(Evidence, evidence_id)
    ev.sha256 = "0" * 64
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()


# --- analysis runs ------------------------------------------------------------

def _populate(db_session, run: AnalysisRun, evidence_id: str) -> None:
    db_session.add_all([
        Claim(claim_id=f"{run.run_id}-C1", run_id=run.run_id, case_id=run.case_id, kind="observation",
              statement="login at 02:17", event_ids=["EV-1"], evidence_ids=[evidence_id]),
        Claim(claim_id=f"{run.run_id}-H1", run_id=run.run_id, case_id=run.case_id, kind="hypothesis",
              statement="unauthorised access", confidence=0.6),
    ])
    db_session.flush()
    db_session.add_all([
        ClaimEdge(run_id=run.run_id, src_claim_id=f"{run.run_id}-C1", dst_claim_id=f"{run.run_id}-H1",
                  relation="supports"),
        HypothesisEval(run_id=run.run_id, hypothesis_claim_id=f"{run.run_id}-H1", verdict="inconclusive",
                       supporting_claim_ids=[f"{run.run_id}-C1"]),
        SourceCoverage(run_id=run.run_id, evidence_id=evidence_id, source="log", family="system_log",
                       event_count=1),
    ])
    db_session.flush()


def test_run_snapshot_freezes_evidence_inputs(client, db_session):
    case_id = _case(client)
    e1 = _upload(client, case_id)
    e2 = _upload(client, case_id, "other_log.csv", LOG_CSV + b"2026-10-18T03:00:00Z,logout,alice,LAPTOP-1\n")
    db_session.get(Evidence, e2["evidence_id"]).status = EVIDENCE_QUARANTINED
    db_session.commit()

    run = create_analysis_run(db_session, case_id, engine_version="test@1")
    db_session.commit()

    assert run.status == "RUNNING"
    assert run.evidence_snapshot == [
        {"evidence_id": e1["evidence_id"], "sha256": e1["sha256"], "status": "ACTIVE", "included": True},
        {"evidence_id": e2["evidence_id"], "sha256": e2["sha256"], "status": "QUARANTINED", "included": False},
    ]
    assert run.input_digest == snapshot_digest(run.evidence_snapshot)


def test_running_run_accepts_children_then_finalizes(client, db_session):
    case_id = _case(client)
    evidence_id = _upload(client, case_id)["evidence_id"]
    run = create_analysis_run(db_session, case_id)
    _populate(db_session, run, evidence_id)
    finalize_run(db_session, run)
    db_session.commit()

    assert run.status == "COMPLETED" and run.completed_at is not None
    assert len(run.claims) == 2
    assert len(run.claim_edges) == len(run.hypothesis_evals) == len(run.source_coverage) == 1


def test_existing_run_unchanged_after_evidence_quarantine(client, db_session):
    case_id = _case(client)
    evidence_id = _upload(client, case_id)["evidence_id"]
    run = create_analysis_run(db_session, case_id)
    finalize_run(db_session, run)
    db_session.commit()
    before = (json.dumps(run.evidence_snapshot, sort_keys=True), run.input_digest)

    db_session.get(Evidence, evidence_id).status = EVIDENCE_QUARANTINED
    db_session.commit()
    db_session.expire_all()

    run = db_session.get(AnalysisRun, run.run_id)
    assert (json.dumps(run.evidence_snapshot, sort_keys=True), run.input_digest) == before
    assert run.evidence_snapshot[0]["status"] == "ACTIVE"


def _finalized_run(client, db_session):
    case_id = _case(client)
    evidence_id = _upload(client, case_id)["evidence_id"]
    run = create_analysis_run(db_session, case_id)
    _populate(db_session, run, evidence_id)
    finalize_run(db_session, run)
    db_session.commit()
    db_session.expire_all()
    return db_session.get(AnalysisRun, run.run_id), evidence_id


@pytest.mark.parametrize("mutate", [
    lambda run: setattr(run, "status", "RUNNING"),
    lambda run: setattr(run, "evidence_snapshot", []),
    lambda run: setattr(run, "error", "edited later"),
])
def test_finalized_run_cannot_be_modified(client, db_session, mutate):
    run, _ = _finalized_run(client, db_session)
    mutate(run)
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()


def test_finalized_run_cannot_be_deleted(client, db_session):
    run, _ = _finalized_run(client, db_session)
    db_session.delete(run)
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()


def test_finalized_run_children_are_immutable(client, db_session):
    run, evidence_id = _finalized_run(client, db_session)

    run.claims[0].statement = "rewritten"
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()

    db_session.delete(db_session.get(AnalysisRun, run.run_id).claim_edges[0])
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()

    db_session.add(SourceCoverage(run_id=run.run_id, evidence_id=evidence_id, event_count=0))
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()


def test_finalize_twice_is_rejected(client, db_session):
    run, _ = _finalized_run(client, db_session)
    with pytest.raises(ValueError):
        finalize_run(db_session, run)


def test_failed_run_records_error_and_is_final(client, db_session):
    case_id = _case(client)
    _upload(client, case_id)
    run = create_analysis_run(db_session, case_id)
    finalize_run(db_session, run, error="parser crashed")
    db_session.commit()
    assert run.status == "FAILED" and run.error == "parser crashed"
    run.error = None
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()


def test_run_for_unknown_case_is_rejected(db_session):
    with pytest.raises(LookupError):
        create_analysis_run(db_session, "NOPE")
