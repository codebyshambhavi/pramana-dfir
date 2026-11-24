"""Role 3: append-only reviewer decisions on immutable reports.

Covers all three decision types, history order, unknown/cross-case IDs, empty rationale and
reviewer label, persistence with self-declared identity, and append-only guards (ORM + triggers).
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.models import CaseReport, CaseReportDecision, ImmutableRecordError

EVIDENCE = Path(__file__).resolve().parents[2] / "datasets" / "sample_case_001" / "evidence" / "system_log.csv"


def _report(client: TestClient, case_id: str) -> str:
    """Case with one evidence file, one completed run and one report of it."""
    res = client.post("/cases", json={"name": f"Decision test {case_id}", "case_id": case_id, "owner": "Test",
                                      "scope": "laptop-01"})
    assert res.status_code == 201, res.text
    up = client.post(f"/cases/{case_id}/evidence", files={"file": (EVIDENCE.name, EVIDENCE.read_bytes())})
    assert up.status_code == 201, up.text
    run = client.post(f"/cases/{case_id}/runs")
    assert run.status_code == 201, run.text
    res = client.post(f"/cases/{case_id}/runs/{run.json()['run_id']}/reports")
    assert res.status_code == 201, res.text
    return res.json()["report_id"]


def _decide(client: TestClient, case_id: str, report_id: str, decision: str, rationale: str = "Checked the evidence",
            reviewer: str = "Reviewer A"):
    return client.post(f"/cases/{case_id}/reports/{report_id}/decisions",
                       json={"decision": decision, "rationale": rationale, "reviewer_label": reviewer})


def test_all_decision_types_append_to_history_in_order(client: TestClient) -> None:
    report_id = _report(client, "CASE-D1")
    created = []
    for decision in ("INCONCLUSIVE", "REJECT", "APPROVE"):
        res = _decide(client, "CASE-D1", report_id, decision, rationale=f"  reason for {decision}  ")
        assert res.status_code == 201, res.text
        body = res.json()
        assert body["decision"] == decision
        assert (body["case_id"], body["report_id"]) == ("CASE-D1", report_id)
        assert body["decision_id"].startswith("DEC-")
        assert body["rationale"] == f"reason for {decision}"
        assert body["reviewer_label"] == "Reviewer A"
        assert body["reviewer_identity_type"] == "self_declared"
        assert body["identity_verified"] is False
        assert body["decided_at"].endswith("+00:00")
        created.append(body)

    history = client.get(f"/cases/CASE-D1/reports/{report_id}/decisions")
    assert history.status_code == 200
    # Append-only: every earlier decision is still there, unchanged, oldest first.
    assert history.json() == created
    assert len({d["decision_id"] for d in created}) == 3


def test_history_is_empty_for_new_report_and_scoped_to_report(client: TestClient) -> None:
    first = _report(client, "CASE-D2")
    run_id = client.get("/cases/CASE-D2/reports").json()[0]["run_id"]
    second = client.post(f"/cases/CASE-D2/runs/{run_id}/reports").json()["report_id"]
    assert client.get(f"/cases/CASE-D2/reports/{first}/decisions").json() == []
    assert _decide(client, "CASE-D2", first, "APPROVE").status_code == 201
    assert client.get(f"/cases/CASE-D2/reports/{second}/decisions").json() == []


@pytest.mark.parametrize("decision", ["approve", "APPROVED", "PENDING", ""])
def test_unknown_decision_is_rejected(client: TestClient, decision: str) -> None:
    report_id = _report(client, f"CASE-DX-{decision or 'EMPTY'}")
    assert _decide(client, f"CASE-DX-{decision or 'EMPTY'}", report_id, decision).status_code == 422


@pytest.mark.parametrize("rationale", ["", "   ", "\n\t"])
def test_empty_rationale_is_rejected(client: TestClient, rationale: str) -> None:
    case_id = f"CASE-DR-{len(rationale)}"
    report_id = _report(client, case_id)
    assert _decide(client, case_id, report_id, "APPROVE", rationale=rationale).status_code == 422
    assert client.get(f"/cases/{case_id}/reports/{report_id}/decisions").json() == []


def test_missing_rationale_or_reviewer_is_rejected(client: TestClient) -> None:
    report_id = _report(client, "CASE-D3")
    url = f"/cases/CASE-D3/reports/{report_id}/decisions"
    assert client.post(url, json={"decision": "APPROVE", "reviewer_label": "R"}).status_code == 422
    assert client.post(url, json={"decision": "APPROVE", "rationale": "ok"}).status_code == 422
    assert _decide(client, "CASE-D3", report_id, "APPROVE", reviewer="   ").status_code == 422


def test_nonexistent_case_or_report_returns_404(client: TestClient) -> None:
    report_id = _report(client, "CASE-D4")
    assert _decide(client, "CASE-D4", "RPT-DOESNOTEXIST", "APPROVE").status_code == 404
    assert client.get("/cases/CASE-D4/reports/RPT-DOESNOTEXIST/decisions").status_code == 404
    assert _decide(client, "CASE-NOPE", report_id, "APPROVE").status_code == 404
    assert client.get(f"/cases/CASE-NOPE/reports/{report_id}/decisions").status_code == 404


def test_cross_case_access_is_blocked(client: TestClient) -> None:
    report_a = _report(client, "CASE-DA")
    _report(client, "CASE-DB")
    assert _decide(client, "CASE-DA", report_a, "APPROVE").status_code == 201

    # Report of case A addressed through case B: same 404 as a missing report, nothing written.
    assert _decide(client, "CASE-DB", report_a, "REJECT").status_code == 404
    assert client.get(f"/cases/CASE-DB/reports/{report_a}/decisions").status_code == 404
    history = client.get(f"/cases/CASE-DA/reports/{report_a}/decisions").json()
    assert [d["decision"] for d in history] == ["APPROVE"]


def test_decision_is_persisted_and_report_is_unchanged(client: TestClient, db_session: Session) -> None:
    report_id = _report(client, "CASE-D5")
    before = db_session.get(CaseReport, report_id)
    sha_before = before.sha256
    decision_id = _decide(client, "CASE-D5", report_id, "REJECT", rationale="Timeline gap", reviewer="Lead").json()[
        "decision_id"]

    db_session.expire_all()
    row = db_session.get(CaseReportDecision, decision_id)
    assert (row.case_id, row.report_id, row.decision) == ("CASE-D5", report_id, "REJECT")
    assert (row.rationale, row.reviewer_label, row.reviewer_identity_type) == ("Timeline gap", "Lead", "self_declared")
    assert row.decided_at is not None
    assert db_session.get(CaseReport, report_id).sha256 == sha_before
    pdf = client.get(f"/cases/CASE-D5/reports/{report_id}/pdf")
    assert pdf.status_code == 200 and pdf.headers["x-report-sha256"] == sha_before


def test_decisions_are_append_only(client: TestClient, db_session: Session) -> None:
    report_id = _report(client, "CASE-D6")
    decision_id = _decide(client, "CASE-D6", report_id, "APPROVE").json()["decision_id"]

    row = db_session.get(CaseReportDecision, decision_id)
    row.decision = "REJECT"
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()

    db_session.delete(db_session.get(CaseReportDecision, decision_id))
    with pytest.raises(ImmutableRecordError):
        db_session.flush()
    db_session.rollback()

    with pytest.raises(Exception, match="append-only"):
        db_session.execute(text("UPDATE case_report_decision SET decision = 'REJECT' WHERE decision_id = :d"),
                           {"d": decision_id})
    db_session.rollback()
    with pytest.raises(Exception, match="append-only"):
        db_session.execute(text("DELETE FROM case_report_decision WHERE decision_id = :d"), {"d": decision_id})
    db_session.rollback()

    history = client.get(f"/cases/CASE-D6/reports/{report_id}/decisions").json()
    assert [(d["decision_id"], d["decision"]) for d in history] == [(decision_id, "APPROVE")]


@pytest.mark.parametrize(
    "case_id, report_id, decision, rationale, identity",
    [
        ("CASE-D7B", "{rid}", "APPROVE", "ok", "self_declared"),   # report of another case
        ("CASE-D7", "RPT-MISSING", "APPROVE", "ok", "self_declared"),  # nonexistent report
        ("CASE-D7", "{rid}", "MAYBE", "ok", "self_declared"),       # unknown decision
        ("CASE-D7", "{rid}", "APPROVE", "   ", "self_declared"),    # blank rationale
        ("CASE-D7", "{rid}", "APPROVE", "ok", "verified"),          # claims a verified identity
    ],
)
def test_database_rejects_invalid_decision_rows(client: TestClient, db_session: Session, case_id, report_id,
                                                decision, rationale, identity) -> None:
    rid = _report(client, "CASE-D7")
    if case_id == "CASE-D7B":
        client.post("/cases", json={"name": "other", "case_id": "CASE-D7B", "owner": "T", "scope": "s"})
    with pytest.raises(Exception, match="invalid report decision|CHECK constraint|FOREIGN KEY"):
        db_session.execute(
            text("INSERT INTO case_report_decision (decision_id, case_id, report_id, decision, rationale, "
                 "reviewer_label, reviewer_identity_type, decided_at) "
                 "VALUES ('DEC-RAW', :c, :r, :d, :ra, 'raw', :i, CURRENT_TIMESTAMP)"),
            {"c": case_id, "r": report_id.format(rid=rid), "d": decision, "ra": rationale, "i": identity},
        )
        db_session.flush()
    db_session.rollback()
