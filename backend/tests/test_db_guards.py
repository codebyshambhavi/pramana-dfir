"""Database-level and bulk-ORM integrity guards (evidence, custody, write-once runs)."""
from __future__ import annotations

import pytest
from sqlalchemy import delete, insert, text, update
from sqlalchemy.exc import DBAPIError

from app.db.claims import ClaimSpec, EdgeSpec
from app.db.models import AnalysisRun, Claim, ClaimEdge, CustodyEntry, EventModel, Evidence, ImmutableRecordError
from app.db.runs import create_analysis_run
from app.db.session import verify_custody_log

LOG_CSV = b"timestamp,action,user,host\n2026-10-18T02:17:00Z,login,alice,LAPTOP-1\n"


@pytest.fixture
def evidence(client):
    client.post("/cases", json={"name": "Guards", "case_id": "CASE-G"})
    body = client.post("/cases/CASE-G/evidence", files={"file": ("log.csv", LOG_CSV)}).json()
    return "CASE-G", body["evidence_id"], body["sha256"]


def _raw_fails(db, sql, params=None, match="PRAMANA"):
    with pytest.raises(DBAPIError, match=match):
        db.execute(text(sql), params or {})
    db.rollback()


# --- evidence -----------------------------------------------------------------

def test_raw_sql_cannot_delete_evidence(db_session, evidence):
    _, evidence_id, _ = evidence
    _raw_fails(db_session, "DELETE FROM evidence WHERE evidence_id = :e", {"e": evidence_id})
    assert db_session.get(Evidence, evidence_id) is not None


def test_raw_sql_cannot_change_intake_hash(db_session, evidence):
    _, evidence_id, sha = evidence
    _raw_fails(db_session, "UPDATE evidence SET sha256 = :s WHERE evidence_id = :e", {"s": "f" * 64, "e": evidence_id})
    assert db_session.get(Evidence, evidence_id).sha256 == sha


def test_raw_sql_same_hash_update_is_allowed(db_session, evidence):
    _, evidence_id, sha = evidence
    db_session.execute(text("UPDATE evidence SET sha256 = :s WHERE evidence_id = :e"), {"s": sha, "e": evidence_id})
    db_session.commit()


@pytest.mark.parametrize("sql", [
    "UPDATE evidence SET status = 'VERIFIED' WHERE evidence_id = :e",
    "UPDATE evidence SET status = 'deleted' WHERE evidence_id = :e",
    "UPDATE evidence SET verify_state = 'OK' WHERE evidence_id = :e",
])
def test_invalid_status_values_are_rejected(db_session, evidence, sql):
    _, evidence_id, _ = evidence
    _raw_fails(db_session, sql, {"e": evidence_id})


def test_orm_bulk_delete_and_update_of_evidence_blocked(db_session, evidence):
    _, evidence_id, _ = evidence
    with pytest.raises(ImmutableRecordError):
        db_session.query(Evidence).filter_by(evidence_id=evidence_id).delete()
    db_session.rollback()
    with pytest.raises(ImmutableRecordError):
        db_session.execute(update(Evidence).where(Evidence.evidence_id == evidence_id).values(sha256="f" * 64))
    db_session.rollback()
    with pytest.raises(ImmutableRecordError):
        db_session.query(Evidence).update({"status": "REMOVED"})  # would skip the custody entry
    db_session.rollback()


# --- custody ------------------------------------------------------------------

def test_raw_sql_cannot_delete_custody(db_session, evidence):
    _, evidence_id, _ = evidence
    _raw_fails(db_session, "DELETE FROM custody_entries WHERE evidence_id = :e", {"e": evidence_id})
    assert db_session.query(CustodyEntry).filter_by(evidence_id=evidence_id).count() == 1


def test_orm_bulk_delete_of_custody_blocked(db_session, evidence):
    with pytest.raises(ImmutableRecordError):
        db_session.execute(delete(CustodyEntry))
    db_session.rollback()


def test_custody_update_still_possible_and_detected(db_session, evidence):
    """G11: custody UPDATE is not blocked, so tampering stays testable; the chain catches it."""
    _, evidence_id, _ = evidence
    db_session.execute(text("UPDATE custody_entries SET actor = 'Mallory' WHERE evidence_id = :e"), {"e": evidence_id})
    db_session.commit()
    ok, message = verify_custody_log(db_session, evidence_id)
    assert not ok and "Tampered" in message


# --- write-once runs ----------------------------------------------------------

def _run(db, case_id, claims=()):
    return create_analysis_run(db, case_id, engine_version="engine@1", assumptions={}, claims=claims)


def _claim(event_id):
    return ClaimSpec("OFFHOURS_SESSION", {"hour": 2}, "ASSERTED", "B", "offhours", "1",
                     edges=[EdgeSpec("event", event_id, "SUPPORTS")])


def test_orm_child_after_run_rejected(db_session, evidence):
    case_id, _, _ = evidence
    run = _run(db_session, case_id)
    db_session.commit()
    db_session.add(Claim(run_id=run.run_id, claim_id="c" * 64, claim_key="k", case_id=case_id,
                         type="OFFHOURS_SESSION", params={}, status="ASSERTED", grade="A", rule_id="r",
                         rule_version="1", assumptions_hash=run.assumptions_hash))
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()


def test_raw_sql_child_after_run_rejected_by_database(db_session, evidence):
    case_id, _, _ = evidence
    run = _run(db_session, case_id)
    db_session.commit()
    params = {"r": run.run_id, "c": case_id, "h": run.assumptions_hash}
    _raw_fails(db_session,
               "INSERT INTO claim (run_id, claim_id, claim_key, case_id, type, params, status, grade, rule_id, "
               "rule_version, assumptions_hash) VALUES (:r, 'late', 'k', :c, 'OFFHOURS_SESSION', '{}', 'ASSERTED', "
               "'A', 'r', '1', :h)", params)
    _raw_fails(db_session, "INSERT INTO claim_edge (run_id, claim_id, ref_kind, ref_id, role) "
                           "VALUES (:r, 'late', 'event', 'x', 'SUPPORTS')", params)
    _raw_fails(db_session, "INSERT INTO hypothesis_eval (run_id) VALUES (:r)", params)
    _raw_fails(db_session, "INSERT INTO source_coverage (run_id) VALUES (:r)", params)


def test_orm_bulk_writes_to_run_tables_blocked(db_session, evidence):
    for stmt in (delete(AnalysisRun), update(Claim).values(status="REFUTED"), delete(ClaimEdge)):
        with pytest.raises(ImmutableRecordError):
            db_session.execute(stmt)
        db_session.rollback()


def test_children_without_run_row_fail_at_commit(db_session, evidence):
    """Deferred FK: claims written for a run that never gets its row cannot commit."""
    case_id, _, _ = evidence
    db_session.execute(insert(Claim.__table__).values(
        run_id="RUN-NEVER", claim_id="c", claim_key="k", case_id=case_id, type="OFFHOURS_SESSION", params={},
        status="ASSERTED", grade="A", rule_id="r", rule_version="1", assumptions_hash="h"))
    with pytest.raises(DBAPIError):
        db_session.commit()
    db_session.rollback()
    assert db_session.query(Claim).count() == 0


def test_database_validates_run_on_insert_cross_run_edge(db_session, evidence):
    """Bypassing the builder: an edge to a claim of another run is rejected when the run row goes in."""
    case_id, _, _ = evidence
    event_id = db_session.query(EventModel).first().event_id
    other = _run(db_session, case_id, [_claim(event_id)])
    db_session.commit()
    foreign_claim = other.claims[0].claim_id
    h = other.assumptions_hash
    db_session.execute(text(
        "INSERT INTO claim (run_id, claim_id, claim_key, case_id, type, params, status, grade, rule_id, "
        "rule_version, assumptions_hash) VALUES ('RUN-NEW', 'c1', 'k', :c, 'OFFHOURS_SESSION', '{}', 'ASSERTED', "
        "'A', 'r', '1', :h)"), {"c": case_id, "h": h})
    db_session.execute(text("INSERT INTO claim_edge (run_id, claim_id, ref_kind, ref_id, role) "
                            "VALUES ('RUN-NEW', 'c1', 'claim', :f, 'SUPPORTS')"), {"f": foreign_claim})
    _raw_fails(db_session,
               "INSERT INTO analysis_run (run_id, case_id, manifest, assumptions_hash, engine_version, "
               "parser_versions, created_at) VALUES ('RUN-NEW', :c, :m, :h, 'e', '{}', CURRENT_TIMESTAMP)",
               {"c": case_id, "h": h, "m": '{"evidence": [], "assumptions": {}}'},
               match="claim edge must target a claim of the same run")


def test_database_validates_manifest_hashes(db_session, evidence):
    case_id, evidence_id, _ = evidence
    bad = '{"evidence": [{"evidence_id": "%s", "sha256": "%s"}], "assumptions": {}}' % (evidence_id, "0" * 64)
    _raw_fails(db_session,
               "INSERT INTO analysis_run (run_id, case_id, manifest, assumptions_hash, engine_version, "
               "parser_versions, created_at) VALUES ('RUN-BAD', :c, :m, 'h', 'e', '{}', CURRENT_TIMESTAMP)",
               {"c": case_id, "m": bad}, match="manifest evidence must be ACTIVE")


def test_database_rejects_event_edge_outside_manifest(client, db_session, evidence):
    case_id, evidence_id, _ = evidence
    event_id = db_session.query(EventModel).filter_by(evidence_id=evidence_id).first().event_id
    client.post(f"/evidence/{evidence_id}/remove")  # evidence no longer ACTIVE -> not in manifest
    db_session.execute(text(
        "INSERT INTO claim (run_id, claim_id, claim_key, case_id, type, params, status, grade, rule_id, "
        "rule_version, assumptions_hash) VALUES ('RUN-E', 'c1', 'k', :c, 'OFFHOURS_SESSION', '{}', 'ASSERTED', "
        "'A', 'r', '1', 'h')"), {"c": case_id})
    db_session.execute(text("INSERT INTO claim_edge (run_id, claim_id, ref_kind, ref_id, role) "
                            "VALUES ('RUN-E', 'c1', 'event', :e, 'SUPPORTS')"), {"e": event_id})
    _raw_fails(db_session,
               "INSERT INTO analysis_run (run_id, case_id, manifest, assumptions_hash, engine_version, "
               "parser_versions, created_at) VALUES ('RUN-E', :c, :m, 'h', 'e', '{}', CURRENT_TIMESTAMP)",
               {"c": case_id, "m": '{"evidence": [], "assumptions": {}}'},
               match="event edge must target an event of manifest evidence")
