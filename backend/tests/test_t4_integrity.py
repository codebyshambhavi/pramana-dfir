"""T4: evidence re-verification, quarantine, soft removal, case integrity and demo tamper."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.db.models import AnalysisRun, CustodyEntry, Evidence
from app.db.runs import create_analysis_run, finalize_run
from app.db.session import NO_FILE_SHA256, verify_custody_log, verify_evidence

LOG_CSV = b"timestamp,action,user,host\n2026-10-18T02:17:00Z,login,alice,LAPTOP-1\n"


@pytest.fixture
def uploaded(client: TestClient, db_session):
    """A case with one uploaded evidence item. Returns (case_id, evidence_id, intake_sha256)."""
    assert client.post("/cases", json={"name": "T4", "case_id": "CASE-T4"}).status_code == 201
    res = client.post("/cases/CASE-T4/evidence", files={"file": ("system_log.csv", LOG_CSV)})
    assert res.status_code == 201, res.text
    body = res.json()
    return "CASE-T4", body["evidence_id"], body["sha256"]


def _evidence(db_session, evidence_id) -> Evidence:
    db_session.expire_all()
    return db_session.get(Evidence, evidence_id)


def _custody(db_session, evidence_id) -> list[CustodyEntry]:
    db_session.expire_all()
    return (db_session.query(CustodyEntry).filter_by(evidence_id=evidence_id)
            .order_by(CustodyEntry.id).all())


def _tamper_file(db_session, evidence_id) -> str:
    path = Path(_evidence(db_session, evidence_id).stored_path)
    path.write_bytes(path.read_bytes() + b"2026-10-18T09:00:00Z,logout,alice,LAPTOP-1\n")
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- verify -------------------------------------------------------------------

def test_verify_untouched_file_marks_verified(client, db_session, uploaded):
    _, evidence_id, sha = uploaded
    res = client.post(f"/evidence/{evidence_id}/verify")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["outcome"] == "MATCH" and body["match"] is True
    assert body["previous_status"] == "ACTIVE" and body["status"] == "VERIFIED"
    assert body["observed_sha256"] == body["intake_sha256"] == sha
    assert body["verified_at"] is not None

    ev = _evidence(db_session, evidence_id)
    assert ev.status == "VERIFIED" and ev.verified_at is not None
    entries = _custody(db_session, evidence_id)
    assert len(entries) == 2
    assert entries[-1].sha256 == sha and "MATCH" in entries[-1].action
    assert verify_custody_log(db_session, evidence_id)[0]


def test_verify_hashes_the_actual_stored_file(client, db_session, uploaded):
    _, evidence_id, sha = uploaded
    tampered = _tamper_file(db_session, evidence_id)
    body = client.post(f"/evidence/{evidence_id}/verify").json()
    assert body["observed_sha256"] == tampered != sha


def test_tampered_file_is_quarantined_and_intake_hash_kept(client, db_session, uploaded):
    _, evidence_id, sha = uploaded
    tampered = _tamper_file(db_session, evidence_id)

    body = client.post(f"/evidence/{evidence_id}/verify").json()
    assert body["outcome"] == "MISMATCH" and body["match"] is False
    assert body["status"] == "QUARANTINED"
    assert body["intake_sha256"] == sha

    ev = _evidence(db_session, evidence_id)
    assert ev.status == "QUARANTINED"
    assert ev.sha256 == sha  # intake hash immutable
    assert ev.verified_at is None
    last = _custody(db_session, evidence_id)[-1]
    assert last.sha256 == tampered  # custody records what was observed
    assert "MISMATCH" in last.action and "QUARANTINED" in last.action
    assert verify_custody_log(db_session, evidence_id)[0]


def test_quarantine_is_sticky_after_file_restored(client, db_session, uploaded):
    _, evidence_id, _ = uploaded
    path = Path(_evidence(db_session, evidence_id).stored_path)
    original = path.read_bytes()
    _tamper_file(db_session, evidence_id)
    client.post(f"/evidence/{evidence_id}/verify")
    path.write_bytes(original)

    body = client.post(f"/evidence/{evidence_id}/verify").json()
    assert body["outcome"] == "MATCH"
    assert body["status"] == "QUARANTINED"


def test_missing_file_is_quarantined(client, db_session, uploaded):
    _, evidence_id, _ = uploaded
    Path(_evidence(db_session, evidence_id).stored_path).unlink()
    body = client.post(f"/evidence/{evidence_id}/verify").json()
    assert body["outcome"] == "MISSING"
    assert body["observed_sha256"] is None
    assert body["status"] == "QUARANTINED"
    assert _custody(db_session, evidence_id)[-1].sha256 == NO_FILE_SHA256


def test_broken_custody_chain_is_quarantined(client, db_session, uploaded):
    _, evidence_id, _ = uploaded
    entry = _custody(db_session, evidence_id)[0]
    entry.actor = "Someone Else"
    db_session.commit()
    body = client.post(f"/evidence/{evidence_id}/verify").json()
    assert body["outcome"] == "CUSTODY_BROKEN"
    assert body["custody_chain_valid"] is False
    assert body["status"] == "QUARANTINED"


def test_verify_twice_appends_two_entries(client, db_session, uploaded):
    _, evidence_id, _ = uploaded
    client.post(f"/evidence/{evidence_id}/verify")
    body = client.post(f"/evidence/{evidence_id}/verify").json()
    assert body["previous_status"] == body["status"] == "VERIFIED"
    assert len(_custody(db_session, evidence_id)) == 3
    assert verify_custody_log(db_session, evidence_id)[0]


def test_verify_accepts_actor(client, db_session, uploaded):
    _, evidence_id, _ = uploaded
    client.post(f"/evidence/{evidence_id}/verify", json={"actor": "Examiner B"})
    assert _custody(db_session, evidence_id)[-1].actor == "Examiner B"


def test_verify_evidence_service_unknown_id(db_session):
    with pytest.raises(LookupError):
        verify_evidence(db_session, "EVID-404")


# --- remove -------------------------------------------------------------------

def test_remove_is_soft_and_keeps_everything(client, db_session, uploaded):
    case_id, evidence_id, sha = uploaded
    path = Path(_evidence(db_session, evidence_id).stored_path)

    res = client.post(f"/evidence/{evidence_id}/remove", json={"reason": "Duplicate upload"})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["previous_status"] == "ACTIVE" and body["status"] == "REMOVED"

    ev = _evidence(db_session, evidence_id)
    assert ev is not None and ev.status == "REMOVED" and ev.sha256 == sha
    assert path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == sha
    entries = _custody(db_session, evidence_id)
    assert len(entries) == 2 and "REMOVED" in entries[-1].action and "Duplicate upload" in entries[-1].action
    assert verify_custody_log(db_session, evidence_id)[0]

    listed = client.get(f"/cases/{case_id}/evidence").json()
    assert [e["status"] for e in listed] == ["REMOVED"]


def test_remove_twice_conflicts_without_new_custody(client, db_session, uploaded):
    _, evidence_id, _ = uploaded
    assert client.post(f"/evidence/{evidence_id}/remove").status_code == 200
    assert client.post(f"/evidence/{evidence_id}/remove").status_code == 409
    assert len(_custody(db_session, evidence_id)) == 2


def test_remove_quarantined_evidence(client, db_session, uploaded):
    _, evidence_id, _ = uploaded
    _tamper_file(db_session, evidence_id)
    client.post(f"/evidence/{evidence_id}/verify")
    body = client.post(f"/evidence/{evidence_id}/remove").json()
    assert body["previous_status"] == "QUARANTINED" and body["status"] == "REMOVED"


def test_remove_reason_is_truncated_to_fit_custody(client, db_session, uploaded):
    _, evidence_id, _ = uploaded
    assert client.post(f"/evidence/{evidence_id}/remove", json={"reason": "x" * 500}).status_code == 200
    assert len(_custody(db_session, evidence_id)[-1].action) <= 128


# --- every state change writes custody ----------------------------------------

def test_every_state_change_appends_exactly_one_custody_entry(client, db_session, uploaded):
    _, evidence_id, _ = uploaded
    steps = [
        lambda: client.post(f"/evidence/{evidence_id}/verify"),       # ACTIVE -> VERIFIED
        lambda: _tamper_file(db_session, evidence_id),                  # file only, no state change
        lambda: client.post(f"/evidence/{evidence_id}/verify"),       # VERIFIED -> QUARANTINED
        lambda: client.post(f"/evidence/{evidence_id}/remove"),       # QUARANTINED -> REMOVED
    ]
    expected_growth = [1, 0, 1, 1]
    count = len(_custody(db_session, evidence_id))
    for step, growth in zip(steps, expected_growth):
        step()
        new_count = len(_custody(db_session, evidence_id))
        assert new_count == count + growth
        count = new_count
    assert verify_custody_log(db_session, evidence_id)[0]


# --- integrity ----------------------------------------------------------------

def test_case_integrity_reports_status_and_is_read_only(client, db_session, uploaded):
    case_id, e1, _ = uploaded
    e2 = client.post(f"/cases/{case_id}/evidence", files={"file": ("second_log.csv", LOG_CSV)}).json()["evidence_id"]
    client.post(f"/evidence/{e1}/verify")
    _tamper_file(db_session, e2)
    client.post(f"/evidence/{e2}/verify")

    before = db_session.query(CustodyEntry).count()
    res = client.get(f"/cases/{case_id}/integrity")
    assert res.status_code == 200, res.text
    body = res.json()
    assert db_session.query(CustodyEntry).count() == before  # no writes

    assert body["case_id"] == case_id
    assert body["intact"] is False
    assert body["summary"]["total"] == 2
    assert body["summary"]["by_status"] == {"ACTIVE": 0, "VERIFIED": 1, "QUARANTINED": 1, "REMOVED": 0}
    assert body["summary"]["broken_custody_chains"] == 0
    assert body["summary"]["never_verified"] == 1
    rows = {r["evidence_id"]: r for r in body["evidence"]}
    assert rows[e1]["status"] == "VERIFIED" and rows[e1]["verified_at"]
    assert rows[e2]["status"] == "QUARANTINED" and rows[e2]["custody_entries"] == 2
    assert all(r["custody_chain_valid"] for r in rows.values())


def test_case_integrity_intact_and_detects_broken_chain(client, db_session, uploaded):
    case_id, evidence_id, _ = uploaded
    assert client.get(f"/cases/{case_id}/integrity").json()["intact"] is True

    entry = _custody(db_session, evidence_id)[0]
    entry.action = "edited"
    db_session.commit()
    body = client.get(f"/cases/{case_id}/integrity").json()
    assert body["intact"] is False
    assert body["summary"]["broken_custody_chains"] == 1
    assert body["evidence"][0]["custody_chain_valid"] is False


def test_case_integrity_does_not_rehash(client, db_session, uploaded):
    case_id, evidence_id, _ = uploaded
    _tamper_file(db_session, evidence_id)
    body = client.get(f"/cases/{case_id}/integrity").json()
    assert body["evidence"][0]["status"] == "ACTIVE"


def test_empty_case_integrity(client):
    client.post("/cases", json={"name": "Empty", "case_id": "CASE-EMPTY"})
    body = client.get("/cases/CASE-EMPTY/integrity").json()
    assert body["intact"] is True and body["summary"]["total"] == 0 and body["evidence"] == []


# --- not found ----------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/evidence/EVID-404/verify",
    "/evidence/EVID-404/remove",
])
def test_unknown_evidence_404(client, path):
    assert client.post(path).status_code == 404


def test_unknown_case_integrity_404(client):
    assert client.get("/cases/NOPE/integrity").status_code == 404


# --- simulate-tamper (demo) ---------------------------------------------------

def test_simulate_tamper_disabled_by_default(client, db_session, uploaded, monkeypatch):
    _, evidence_id, sha = uploaded
    monkeypatch.delenv("DEMO_MODE", raising=False)
    path = Path(_evidence(db_session, evidence_id).stored_path)
    assert client.post(f"/evidence/{evidence_id}/simulate-tamper").status_code == 404
    monkeypatch.setenv("DEMO_MODE", "0")
    assert client.post(f"/evidence/{evidence_id}/simulate-tamper").status_code == 404
    assert hashlib.sha256(path.read_bytes()).hexdigest() == sha
    assert len(_custody(db_session, evidence_id)) == 1


def test_simulate_tamper_then_verify_quarantines(client, db_session, uploaded, monkeypatch):
    case_id, evidence_id, sha = uploaded
    monkeypatch.setenv("DEMO_MODE", "1")
    res = client.post(f"/evidence/{evidence_id}/simulate-tamper")
    assert res.status_code == 200, res.text
    demo = res.json()
    assert demo["demo"] is True and demo["tampered_sha256"] != sha
    assert demo["status"] == "ACTIVE"  # status only changes on verify
    assert _custody(db_session, evidence_id)[-1].actor == "DEMO_MODE"

    body = client.post(f"/evidence/{evidence_id}/verify").json()
    assert body["status"] == "QUARANTINED"
    assert body["observed_sha256"] == demo["tampered_sha256"]
    assert _evidence(db_session, evidence_id).sha256 == sha
    assert verify_custody_log(db_session, evidence_id)[0]
    assert client.get(f"/cases/{case_id}/integrity").json()["intact"] is False


def test_simulate_tamper_unknown_and_missing_file(client, db_session, uploaded, monkeypatch):
    _, evidence_id, _ = uploaded
    monkeypatch.setenv("DEMO_MODE", "1")
    assert client.post("/evidence/EVID-404/simulate-tamper").status_code == 404
    Path(_evidence(db_session, evidence_id).stored_path).unlink()
    assert client.post(f"/evidence/{evidence_id}/simulate-tamper").status_code == 409


# --- existing runs stay immutable ---------------------------------------------

def test_quarantine_does_not_change_existing_run(client, db_session, uploaded):
    case_id, evidence_id, sha = uploaded
    run = create_analysis_run(db_session, case_id)
    finalize_run(db_session, run)
    db_session.commit()
    run_id, digest = run.run_id, run.input_digest

    _tamper_file(db_session, evidence_id)
    assert client.post(f"/evidence/{evidence_id}/verify").json()["status"] == "QUARANTINED"
    assert client.post(f"/evidence/{evidence_id}/remove").status_code == 200

    db_session.expire_all()
    run = db_session.get(AnalysisRun, run_id)
    assert run.input_digest == digest
    assert run.evidence_snapshot == [{"evidence_id": evidence_id, "sha256": sha, "status": "ACTIVE", "included": True}]

    new_run = create_analysis_run(db_session, case_id)
    assert new_run.evidence_snapshot[0]["status"] == "REMOVED"
    assert new_run.evidence_snapshot[0]["included"] is False
