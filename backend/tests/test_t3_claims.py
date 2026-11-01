"""T3: content-addressed claims, enums, same-run integrity and lineage."""
from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.db.claims import (
    H,
    ClaimSpec,
    ClaimValidationError,
    EdgeSpec,
    claim_lineage,
    compute_claim_id,
    compute_claim_key,
    verify_claim_id,
)
from app.db.models import Claim, ClaimEdge, EventModel, ImmutableRecordError
from app.db.runs import create_analysis_run

LOG_CSV = (b"timestamp,action,user,host\n"
           b"2026-10-18T02:17:00Z,login,alice,LAPTOP-1\n"
           b"2026-10-18T02:40:00Z,archive_create,alice,LAPTOP-1\n")
ASSUMPTIONS = {"case_timezone": "UTC"}


@pytest.fixture
def case(client, db_session):
    """Case with two ACTIVE evidence items. Returns (case_id, {evidence_id: [event_ids]}, {evidence_id: sha})."""
    client.post("/cases", json={"name": "Claims", "case_id": "CASE-C"})
    events, shas = {}, {}
    for name in ("log_a.csv", "log_b.csv"):
        body = client.post("/cases/CASE-C/evidence", files={"file": (name, LOG_CSV)}).json()
        shas[body["evidence_id"]] = body["sha256"]
        events[body["evidence_id"]] = sorted(
            e.event_id for e in db_session.query(EventModel).filter_by(evidence_id=body["evidence_id"]))
    return "CASE-C", events, shas


def _spec(event_ids, *, role="SUPPORTS", type_="OFFHOURS_SESSION", params=None, label=None, extra_edges=(),
          status="ASSERTED", grade="B", rule_version="1.0.0"):
    edges = [EdgeSpec("event", e, role, weight=1.0, reason_code="LOGIN_0217", family="system_log")
             for e in event_ids]
    return ClaimSpec(type=type_, params=params or {"actor": "alice", "hour": 2}, status=status, grade=grade,
                     rule_id="offhours", rule_version=rule_version, edges=edges + list(extra_edges), label=label)


def _run(db, case_id, claims, **kw):
    return create_analysis_run(db, case_id, engine_version="engine@1", assumptions=kw.pop("assumptions", ASSUMPTIONS),
                               claims=claims, **kw)


# --- content addressing -------------------------------------------------------

def test_claim_id_matches_h_formula(case, db_session):
    case_id, events, shas = case
    evid, ev_ids = next(iter(events.items()))
    run = _run(db_session, case_id, [_spec(ev_ids)])
    db_session.commit()
    claim = run.claims[0]

    key = H("OFFHOURS_SESSION", {"actor": "alice", "hour": 2})
    assert claim.claim_key == key == compute_claim_key("OFFHOURS_SESSION", {"hour": 2, "actor": "alice"})
    expected = H(key, sorted(ev_ids), [shas[evid]], "offhours@1.0.0", H(ASSUMPTIONS))
    assert claim.claim_id == expected
    assert claim.assumptions_hash == run.assumptions_hash
    assert verify_claim_id(db_session, run.run_id, claim.claim_id)


def test_claim_id_is_deterministic_and_input_sensitive(case):
    _, events, shas = case
    evid, ev_ids = next(iter(events.items()))
    base = dict(claim_key="k", input_event_ids=ev_ids, input_evidence_sha256s=[shas[evid]],
                rule_id="r", rule_version="1", assumptions_hash="a")
    ref = compute_claim_id(**base)
    assert compute_claim_id(**{**base, "input_event_ids": list(reversed(ev_ids))}) == ref  # order-free
    for change in ({"claim_key": "k2"}, {"input_event_ids": ev_ids[:1]}, {"input_evidence_sha256s": ["0" * 64]},
                   {"rule_version": "2"}, {"rule_id": "r2"}, {"assumptions_hash": "b"}):
        assert compute_claim_id(**{**base, **change}) != ref, change


def test_contradicting_events_do_not_change_identity(case, db_session):
    case_id, events, _ = case
    (ev_a, ids_a), (_, ids_b) = events.items()
    plain = _run(db_session, case_id, [_spec(ids_a)])
    contested = _run(db_session, case_id, [_spec(
        ids_a, status="CONTESTED", extra_edges=[EdgeSpec("event", ids_b[0], "CONTRADICTS")])])
    db_session.commit()
    assert plain.claims[0].claim_id == contested.claims[0].claim_id
    assert verify_claim_id(db_session, contested.run_id, contested.claims[0].claim_id)


def test_same_claim_in_two_runs_is_stored_per_run(case, db_session):
    case_id, events, _ = case
    ids = next(iter(events.values()))
    r1 = _run(db_session, case_id, [_spec(ids, status="ASSERTED")])
    r2 = _run(db_session, case_id, [_spec(ids, status="CORROBORATED", grade="A")], parent_run_id=r1.run_id)
    db_session.commit()
    c1, c2 = r1.claims[0], r2.claims[0]
    assert c1.claim_id == c2.claim_id  # reproducible identity
    assert (c1.status, c2.status) == ("ASSERTED", "CORROBORATED")  # per-run evaluation
    assert db_session.query(Claim).filter_by(claim_id=c1.claim_id).count() == 2


def test_tampering_with_stored_claim_is_detectable(case, db_session):
    case_id, events, _ = case
    run = _run(db_session, case_id, [_spec(next(iter(events.values())))])
    db_session.commit()
    claim_id = run.claims[0].claim_id
    # Simulate tampering below the guards (triggers off for this connection only).
    db_session.execute(text("DROP TRIGGER trg_claim_no_update"))
    db_session.execute(text("UPDATE claim SET params = '{\"actor\": \"bob\", \"hour\": 2}' WHERE claim_id = :c"),
                       {"c": claim_id})
    db_session.commit()
    db_session.expire_all()
    assert not verify_claim_id(db_session, run.run_id, claim_id)


# --- enums and validation -----------------------------------------------------

@pytest.mark.parametrize("field,value", [("type_", "SOMETHING_ELSE"), ("status", "PROBABLE"), ("grade", "D")])
def test_claim_enums_are_enforced(case, db_session, field, value):
    case_id, events, _ = case
    with pytest.raises(ClaimValidationError):
        _run(db_session, case_id, [_spec(next(iter(events.values())), **{field: value})])


@pytest.mark.parametrize("ref_kind,role", [("file", "SUPPORTS"), ("event", "IMPLIES")])
def test_edge_enums_are_enforced(case, db_session, ref_kind, role):
    case_id, events, _ = case
    ev = next(iter(events.values()))[0]
    spec = ClaimSpec("OFFHOURS_SESSION", {}, "ASSERTED", "A", "r", "1", edges=[EdgeSpec(ref_kind, ev, role)])
    with pytest.raises(ClaimValidationError):
        _run(db_session, case_id, [spec])


def test_db_check_constraints_reject_bad_enum(case, db_session):
    case_id, _, _ = case
    with pytest.raises(DBAPIError):
        db_session.execute(text(
            "INSERT INTO claim (run_id, claim_id, claim_key, case_id, type, params, status, grade, rule_id, "
            "rule_version, assumptions_hash) VALUES ('RUN-X', 'c', 'k', :case, 'BOGUS', '{}', 'ASSERTED', 'A', "
            "'r', '1', 'h')"), {"case": case_id})
    db_session.rollback()


def test_event_from_non_active_evidence_is_rejected(client, case, db_session):
    case_id, events, _ = case
    (removed, ids), _ = events.items()
    client.post(f"/evidence/{removed}/remove")
    with pytest.raises(ClaimValidationError, match="not ACTIVE"):
        _run(db_session, case_id, [_spec(ids)])


def test_event_from_other_case_is_rejected(client, case, db_session):
    case_id, _, _ = case
    client.post("/cases", json={"name": "Other", "case_id": "CASE-O"})
    client.post("/cases/CASE-O/evidence", files={"file": ("o.csv", LOG_CSV)})
    other = db_session.query(EventModel).filter_by(case_id="CASE-O").first().event_id
    with pytest.raises(ClaimValidationError, match="belongs to case"):
        _run(db_session, case_id, [_spec([other])])


def test_unknown_event_is_rejected(case, db_session):
    case_id, _, _ = case
    with pytest.raises(ClaimValidationError, match="does not exist"):
        _run(db_session, case_id, [_spec(["no-such-event"])])


def test_claim_edges_resolve_labels_within_the_run(case, db_session):
    case_id, events, _ = case
    (_, ids_a), (_, ids_b) = events.items()
    base = _spec(ids_a, label="login")
    derived = _spec(ids_b, type_="SAME_OBJECT_FLOW", params={"object": "secret.zip"},
                    extra_edges=[EdgeSpec("claim", "login", "SUPPORTS")])
    run = _run(db_session, case_id, [base, derived])
    db_session.commit()
    by_type = {c.type: c for c in run.claims}
    edge = [e for e in by_type["SAME_OBJECT_FLOW"].edges if e.ref_kind == "claim"][0]
    assert edge.ref_id == by_type["OFFHOURS_SESSION"].claim_id and edge.run_id == run.run_id


def test_claim_edge_to_claim_of_another_run_is_rejected(case, db_session):
    case_id, events, _ = case
    (_, ids_a), (_, ids_b) = events.items()
    other = _run(db_session, case_id, [_spec(ids_a)])
    foreign_claim = other.claims[0].claim_id
    spec = _spec(ids_b, extra_edges=[EdgeSpec("claim", foreign_claim, "SUPPORTS")])
    with pytest.raises(ClaimValidationError, match="not a claim of this run"):
        _run(db_session, case_id, [spec])


def test_duplicate_claim_in_one_run_is_rejected(case, db_session):
    case_id, events, _ = case
    ids = next(iter(events.values()))
    with pytest.raises(ClaimValidationError, match="duplicate claim"):
        _run(db_session, case_id, [_spec(ids), _spec(ids, status="REFUTED")])


def test_claims_and_edges_are_write_once(case, db_session):
    case_id, events, _ = case
    run = _run(db_session, case_id, [_spec(next(iter(events.values())))])
    db_session.commit()
    claim = run.claims[0]
    claim.status = "REFUTED"
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()
    db_session.delete(db_session.query(ClaimEdge).filter_by(run_id=run.run_id).first())
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()


# --- lineage ------------------------------------------------------------------

def test_lineage_reaches_evidence_hashes(case, db_session):
    case_id, events, shas = case
    (ev_a, ids_a), (ev_b, ids_b) = events.items()
    base = _spec(ids_a, label="login")
    derived = _spec(ids_b, type_="SAME_OBJECT_FLOW", params={"object": "secret.zip"},
                    extra_edges=[EdgeSpec("claim", "login", "SUPPORTS")])
    run = _run(db_session, case_id, [base, derived])
    db_session.commit()
    top = next(c for c in run.claims if c.type == "SAME_OBJECT_FLOW")

    lineage = claim_lineage(db_session, run.run_id, top.claim_id)
    assert {e["evidence_sha256"] for e in lineage["events"]} == {shas[ev_b]}
    nested = lineage["claims"][0]["lineage"]
    assert {e["evidence_sha256"] for e in nested["events"]} == {shas[ev_a]}
    assert all(e["evidence_id"] and e["artifact_ref"] for e in lineage["events"] + nested["events"])
