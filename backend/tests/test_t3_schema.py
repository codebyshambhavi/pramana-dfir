"""T3: H″ schema, Event v1.1 persistence, write-once runs, manifest and parser_versions."""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, text
from sqlalchemy.exc import DBAPIError

from app.db.claims import H
from app.db.models import AnalysisRun, EventModel, Evidence, ImmutableRecordError
from app.db.runs import RunValidationError, create_analysis_run

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLE_DIR = REPO_ROOT / "datasets" / "sample_case_001"
EVENT_SCHEMA = json.loads((REPO_ROOT / "contracts" / "event.schema.json").read_text(encoding="utf-8"))
LOG_CSV = b"timestamp,action,user,host\n2026-10-18T02:17:00Z,login,alice,LAPTOP-1\n"
ASSUMPTIONS = {"case_timezone": "UTC", "source_clocks": {}}


def _case(client: TestClient, case_id: str = "CASE-T3") -> str:
    assert client.post("/cases", json={"name": "T3", "case_id": case_id}).status_code == 201
    return case_id


def _upload(client: TestClient, case_id: str, name: str = "system_log.csv", content: bytes = LOG_CSV) -> dict:
    res = client.post(f"/cases/{case_id}/evidence", files={"file": (name, content)})
    assert res.status_code == 201, res.text
    return res.json()


def _run(db, case_id, **kw):
    kw.setdefault("engine_version", "pramana-engine@0.1.0")
    kw.setdefault("assumptions", ASSUMPTIONS)
    return create_analysis_run(db, case_id, **kw)


# --- schema -------------------------------------------------------------------

EXPECTED_COLUMNS = {
    "analysis_run": {"run_id", "case_id", "parent_run_id", "manifest", "assumptions_hash", "engine_version",
                     "parser_versions", "ranking_hash", "created_at"},
    "claim": {"claim_id", "claim_key", "run_id", "case_id", "type", "params", "status", "grade", "rule_id",
              "rule_version", "assumptions_hash"},
    "claim_edge": {"run_id", "claim_id", "ref_kind", "ref_id", "role", "weight", "reason_code", "family"},
    "hypothesis_eval": {"id", "run_id"},
    "source_coverage": {"id", "run_id"},
}


@pytest.mark.parametrize("table", sorted(EXPECTED_COLUMNS))
def test_t3_tables_have_exactly_the_h_columns(table, db_session):
    insp = inspect(db_session.get_bind())
    assert {c["name"] for c in insp.get_columns(table)} == EXPECTED_COLUMNS[table]


def test_t3_primary_keys(db_session):
    insp = inspect(db_session.get_bind())
    assert insp.get_pk_constraint("analysis_run")["constrained_columns"] == ["run_id"]
    assert insp.get_pk_constraint("claim")["constrained_columns"] == ["run_id", "claim_id"]
    assert insp.get_pk_constraint("claim_edge")["constrained_columns"] == [
        "run_id", "claim_id", "ref_kind", "ref_id", "role"]


def test_t3_foreign_keys(db_session):
    insp = inspect(db_session.get_bind())
    fks = {t: {(tuple(fk["constrained_columns"]), fk["referred_table"]) for fk in insp.get_foreign_keys(t)}
           for t in EXPECTED_COLUMNS}
    assert {(("case_id",), "cases"), (("parent_run_id",), "analysis_run")} <= fks["analysis_run"]
    assert {(("run_id",), "analysis_run"), (("case_id",), "cases")} <= fks["claim"]
    assert {(("run_id", "claim_id"), "claim"), (("run_id",), "analysis_run")} <= fks["claim_edge"]
    assert (("run_id",), "analysis_run") in fks["hypothesis_eval"]
    assert (("run_id",), "analysis_run") in fks["source_coverage"]


def test_sqlite_foreign_keys_enabled(db_session):
    assert db_session.execute(text("PRAGMA foreign_keys")).scalar() == 1


def test_evidence_and_event_columns(db_session):
    insp = inspect(db_session.get_bind())
    assert {"status", "verified_at", "verify_state"} <= {c["name"] for c in insp.get_columns("evidence")}
    assert {"parser_version", "tz_assumption", "family"} <= {c["name"] for c in insp.get_columns("events")}


# --- Event v1.1 persistence (unchanged from T3) -------------------------------

def test_event_v11_fields_are_persisted_and_served(client, db_session):
    case_id = _case(client)
    for name in ("system_log.csv", "browser_history.csv", "chat_export.json"):
        _upload(client, case_id, name, (SAMPLE_DIR / name).read_bytes())
    rows = db_session.query(EventModel).filter_by(case_id=case_id).all()
    assert rows and all(r.parser_version and "@" in r.parser_version and r.tz_assumption and r.family for r in rows)
    served = client.get(f"/cases/{case_id}/events").json()
    assert len(served) == len(rows)
    for event in served:
        jsonschema.validate(event, EVENT_SCHEMA)


# --- runs: manifest, assumptions, parser_versions -----------------------------

def test_run_has_nine_fields_and_active_only_manifest(client, db_session):
    case_id = _case(client)
    e1 = _upload(client, case_id)
    e2 = _upload(client, case_id, "second.csv", LOG_CSV)
    e3 = _upload(client, case_id, "third.csv", LOG_CSV)
    client.post(f"/evidence/{e3['evidence_id']}/remove")

    run = _run(db_session, case_id)
    db_session.commit()

    data = run.to_dict()
    assert set(data) == EXPECTED_COLUMNS["analysis_run"]
    assert data["run_id"].startswith("RUN-")
    assert data["parent_run_id"] is None and data["ranking_hash"] is None
    assert data["manifest"] == {
        "evidence": [
            {"evidence_id": e1["evidence_id"], "sha256": e1["sha256"]},
            {"evidence_id": e2["evidence_id"], "sha256": e2["sha256"]},
        ],
        "assumptions": ASSUMPTIONS,
    }
    assert data["assumptions_hash"] == H(ASSUMPTIONS)


def test_parser_versions_derived_from_stored_events(client, db_session):
    case_id = _case(client)
    _upload(client, case_id, "system_log.csv", (SAMPLE_DIR / "system_log.csv").read_bytes())
    _upload(client, case_id, "browser_history.csv", (SAMPLE_DIR / "browser_history.csv").read_bytes())
    stored = sorted({v for (v,) in db_session.query(EventModel.parser_version).filter_by(case_id=case_id)})

    run = _run(db_session, case_id)
    assert run.parser_versions == {"known": stored, "unknown_evidence_ids": []}


def test_legacy_events_are_reported_unknown_not_invented(client, db_session):
    case_id = _case(client)
    legacy = _upload(client, case_id)["evidence_id"]
    modern = _upload(client, case_id, "b.csv", LOG_CSV)["evidence_id"]
    db_session.execute(text("UPDATE events SET parser_version = NULL WHERE evidence_id = :e"), {"e": legacy})
    db_session.commit()
    known = sorted({v for (v,) in db_session.query(EventModel.parser_version).filter_by(evidence_id=modern)})

    run = _run(db_session, case_id)
    assert run.parser_versions == {"known": known, "unknown_evidence_ids": [legacy]}


def test_parser_versions_ignore_quarantined_and_removed_evidence(client, db_session):
    case_id = _case(client)
    _upload(client, case_id, "system_log.csv", (SAMPLE_DIR / "system_log.csv").read_bytes())
    removed = _upload(client, case_id, "browser_history.csv", (SAMPLE_DIR / "browser_history.csv").read_bytes())
    client.post(f"/evidence/{removed['evidence_id']}/remove")
    browser_versions = {v for (v,) in db_session.query(EventModel.parser_version)
                        .filter_by(evidence_id=removed["evidence_id"])}

    run = _run(db_session, case_id)
    assert not browser_versions & set(run.parser_versions["known"])


def test_parent_run_and_ranking_hash(client, db_session):
    case_id = _case(client)
    _upload(client, case_id)
    parent = _run(db_session, case_id)
    child = _run(db_session, case_id, parent_run_id=parent.run_id, ranking_hash="a" * 64)
    db_session.commit()
    assert child.parent_run_id == parent.run_id and child.ranking_hash == "a" * 64

    with pytest.raises(RunValidationError):
        _run(db_session, case_id, ranking_hash="not-a-hash")
    with pytest.raises(RunValidationError):
        _run(db_session, case_id, parent_run_id="RUN-NOPE")
    _case(client, "CASE-OTHER")
    with pytest.raises(RunValidationError):
        _run(db_session, "CASE-OTHER", parent_run_id=parent.run_id)


def test_run_for_unknown_case_is_rejected(db_session):
    with pytest.raises(LookupError):
        _run(db_session, "NOPE")


# --- write-once runs ----------------------------------------------------------

def test_existing_run_unchanged_after_evidence_quarantine(client, db_session):
    case_id = _case(client)
    ev = _upload(client, case_id)
    run = _run(db_session, case_id)
    db_session.commit()
    before = json.dumps(run.to_dict(), sort_keys=True)

    path = Path(db_session.get(Evidence, ev["evidence_id"]).stored_path)
    path.write_bytes(path.read_bytes() + b"x")
    assert client.post(f"/evidence/{ev['evidence_id']}/verify").json()["status"] == "QUARANTINED"

    db_session.expire_all()
    assert json.dumps(db_session.get(AnalysisRun, run.run_id).to_dict(), sort_keys=True) == before


@pytest.mark.parametrize("mutate", [
    lambda run: setattr(run, "manifest", {"evidence": [], "assumptions": {}}),
    lambda run: setattr(run, "ranking_hash", "b" * 64),
    lambda run: setattr(run, "engine_version", "other"),
])
def test_run_rows_cannot_be_modified_via_orm(client, db_session, mutate):
    case_id = _case(client)
    _upload(client, case_id)
    run = _run(db_session, case_id)
    db_session.commit()
    mutate(run)
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()


def test_run_rows_cannot_be_modified_or_deleted_via_sql(client, db_session):
    case_id = _case(client)
    _upload(client, case_id)
    run_id = _run(db_session, case_id).run_id
    db_session.commit()
    for sql in ("UPDATE analysis_run SET ranking_hash = 'x' WHERE run_id = :r",
                "DELETE FROM analysis_run WHERE run_id = :r"):
        with pytest.raises(DBAPIError, match="PRAMANA"):
            db_session.execute(text(sql), {"r": run_id})
        db_session.rollback()
    assert db_session.get(AnalysisRun, run_id) is not None
