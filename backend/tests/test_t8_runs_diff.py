"""Role 3 / T8: Immutable Runs, Invalidation, and Semantic Run Diffing Tests.

Tests:
1. Write-once database immutability: run rows cannot be updated, deleted, or mutated.
2. POST /cases/{id}/runs creates complete immutable run with ranking_hash, hypotheses, and H0.
3. GET /runs/{id} returns reproducible run and verifies ranking_hash.
4. Evidence quarantine / soft-removal invalidates previous analysis runs (is_valid=False).
5. GET /runs/{a}/diff/{b} compares two immutable runs matching claims by claim_key:
   - Traces added, removed, modified, and unchanged claims
   - Traces hypothesis status shifts (e.g. LEADING -> WEAKENED)
   - Explains root cause of conclusion changes
6. Re-running analysis after evidence removal creates an updated child run without mutating historical runs.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.models import AnalysisRun, Claim, ImmutableRecordError
from app.services.runs import diff_runs, execute_analysis_run, get_run_details


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
def run_case_setup(client: TestClient):
    case_id = "CASE-RUN-DIFF-TEST"
    client.post("/cases", json={"name": "Run Diff & Immutability Test", "case_id": case_id})

    res_ev1 = client.post(f"/cases/{case_id}/evidence", files={"file": ("sys.csv", LOG_EVIDENCE)})
    res_ev2 = client.post(f"/cases/{case_id}/evidence", files={"file": ("browser.csv", BROWSER_EVIDENCE)})

    ev1_id = res_ev1.json()["evidence_id"]
    ev2_id = res_ev2.json()["evidence_id"]

    return case_id, ev1_id, ev2_id


def test_immutable_run_creation_and_reproducible_retrieval(client: TestClient, run_case_setup):
    case_id, ev1_id, ev2_id = run_case_setup

    # 1. Create Run 1
    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    assert res.status_code == 201
    run_1_data = res.json()
    run_1_id = run_1_data["run_id"]
    assert run_1_id.startswith("RUN-")
    assert run_1_data["claims_count"] > 0
    assert run_1_data["ranking_hash"] is not None
    assert len(run_1_data["ranked_hypotheses"]) == 3
    assert run_1_data["reconstruction"] is not None
    assert run_1_data["h0_residual"] is not None

    # Top hypothesis should be H1 (Insider Exfiltration)
    top_hyp = run_1_data["ranked_hypotheses"][0]
    assert top_hyp["id"] == "H1"
    assert top_hyp["status"] == "LEADING"

    # 2. Retrieve Run 1 via GET /runs/{id}
    res_get = client.get(f"/runs/{run_1_id}")
    assert res_get.status_code == 200
    retrieved = res_get.json()
    assert retrieved["run_id"] == run_1_id
    assert retrieved["ranking_hash"] == run_1_data["ranking_hash"]
    assert retrieved["ranking_hash_verified"] is True
    assert retrieved["is_valid"] is True
    assert retrieved["validity"] == "VALID"
    assert retrieved["outcome"] == "LEADING"


def test_database_level_run_immutability(client: TestClient, db_session: Session, run_case_setup):
    case_id, _, _ = run_case_setup

    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_id = res.json()["run_id"]

    run_obj = db_session.get(AnalysisRun, run_id)
    assert run_obj is not None

    # 1. Attempt to update run_obj via ORM must fail
    with pytest.raises(ImmutableRecordError, match="write-once"):
        run_obj.engine_version = "pramana-engine@2.0.0"
        db_session.flush()
    db_session.rollback()

    # 2. Attempt to delete run_obj via ORM must fail
    with pytest.raises(ImmutableRecordError, match="immutable and never deleted"):
        db_session.delete(run_obj)
        db_session.flush()
    db_session.rollback()

    # 3. Attempt to insert new claim into existing run must fail
    with pytest.raises(ImmutableRecordError, match="already exists"):
        bad_claim = Claim(
            run_id=run_id,
            claim_id="FAKE-CLAIM-ID",
            claim_key="FAKE-KEY",
            case_id=case_id,
            type="SAME_OBJECT_FLOW",
            params={},
            status="ASSERTED",
            grade="A",
            rule_id="fake_rule",
            rule_version="1.0.0",
            assumptions_hash="0" * 64,
        )
        db_session.add(bad_claim)
        db_session.flush()
    db_session.rollback()


def test_evidence_quarantine_invalidates_run_and_diffs_against_new_run(client: TestClient, run_case_setup):
    case_id, ev1_id, ev2_id = run_case_setup

    # 1. Create Run A (baseline)
    res_a = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    run_a_id = res_a.json()["run_id"]
    assert res_a.json()["ranked_hypotheses"][0]["id"] == "H1"
    assert res_a.json()["ranked_hypotheses"][0]["status"] == "LEADING"

    # 2. Soft-remove / Quarantine evidence 2 (browser.csv upload evidence)
    res_rem = client.post(
        f"/evidence/{ev2_id}/remove",
        json={"actor": "Lead Investigator", "reason": "Chain of custody compromised"},
    )
    assert res_rem.status_code == 200
    assert res_rem.json()["status"] == "REMOVED"

    # 3. Check Run A validity -> MUST BE INVALIDATED
    res_a_check = client.get(f"/runs/{run_a_id}")
    assert res_a_check.status_code == 200
    details_a = res_a_check.json()
    assert details_a["is_valid"] is False
    assert details_a["validity"] == "INVALIDATED"
    assert any(ev2_id in r for r in details_a["invalidation_reasons"])

    # 4. Create Run B (post-quarantine) referencing Run A as parent
    res_b = client.post(
        f"/cases/{case_id}/runs",
        json={
            "engine_version": "pramana-engine@1.0.0",
            "assumptions": {"case_timezone": "UTC"},
            "parent_run_id": run_a_id,
        },
    )
    assert res_b.status_code == 201
    run_b_id = res_b.json()["run_id"]
    details_b = res_b.json()
    assert details_b["parent_run_id"] == run_a_id

    # 5. Diff Run A and Run B via GET /runs/{a}/diff/{b}
    res_diff = client.get(f"/runs/{run_a_id}/diff/{run_b_id}")
    assert res_diff.status_code == 200
    diff_data = res_diff.json()

    # Check evidence diff
    assert len(diff_data["evidence_diff"]["removed"]) == 1
    assert diff_data["evidence_diff"]["removed"][0]["evidence_id"] == ev2_id

    # Check claims diff matching by claim_key
    assert diff_data["claims_diff"]["removed_count"] > 0
    removed_types = [c["type"] for c in diff_data["claims_diff"]["removed_claims"]]
    assert "SAME_OBJECT_FLOW" in removed_types  # The upload was removed!

    # Check hypothesis diffs and root cause explanation
    assert len(diff_data["hypothesis_diffs"]) == 3
    assert "root_cause_analysis" in diff_data
    assert ev2_id in diff_data["root_cause_analysis"]


def test_analyze_case_alias_creates_immutable_run(client: TestClient, run_case_setup):
    """POST /cases/{id}/analyze creates an immutable analysis run."""
    case_id, _, _ = run_case_setup
    res = client.post(f"/cases/{case_id}/analyze")
    assert res.status_code == 200
    data = res.json()
    assert "run_id" in data
    assert data["run_id"] is not None
    assert data["run_id"].startswith("RUN-")
    assert data["claims_created"] > 0

    # Verify that the created run exists in /runs/{id}
    res_run = client.get(f"/runs/{data['run_id']}")
    assert res_run.status_code == 200
    assert res_run.json()["case_id"] == case_id
