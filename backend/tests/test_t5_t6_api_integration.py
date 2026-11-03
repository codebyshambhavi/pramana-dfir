"""Integration tests for T5 and T6 API endpoints and lifecycle workflows.

Tests:
1. POST /cases/{case_id}/runs creates an immutable run with T5+T6 outputs
2. GET /cases/{case_id}/runs lists runs
3. GET /cases/{case_id}/runs/{run_id} returns run metadata and manifest
4. GET /cases/{case_id}/runs/{run_id}/claims retrieves content-addressed claims
5. GET /runs/{run_id}/claims/{claim_id} retrieves a specific claim
6. GET /runs/{run_id}/claims/{claim_id}/lineage resolves claim to evidence SHA-256
7. GET /cases/{case_id}/runs/{run_id}/correlations returns candidates and promoted links
8. Case and run ownership validation (404/422 on mismatch)
9. Re-running analysis or adding evidence creates a new run without mutating old run
10. Full end-to-end integration: upload -> analyze -> claims -> lineage
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.models import AnalysisRun, Claim


LOG_DATA = (
    b"timestamp,action,actor,device,ip,object\n"
    b"2026-10-18T10:00:00Z,archive_create,mira,laptop-01,10.0.0.1,archive.tar.gz\n"
)

BROWSER_DATA = (
    b"timestamp,action,url,actor,device,ip\n"
    b"2026-10-18T10:04:00Z,upload,https://vault.test/upload/archive.tar.gz,mira,laptop-01,10.0.0.1\n"
)


def test_t5_t6_api_full_lifecycle(client: TestClient, db_session: Session):
    case_id = "CASE-API-LIFECYCLE"
    # 1. Create case
    res_case = client.post("/cases", json={"name": "API Lifecycle Test", "case_id": case_id})
    assert res_case.status_code == 201

    # 2. Upload evidence
    res_ev1 = client.post(f"/cases/{case_id}/evidence", files={"file": ("sys.csv", LOG_DATA)})
    res_ev2 = client.post(f"/cases/{case_id}/evidence", files={"file": ("history.csv", BROWSER_DATA)})
    assert res_ev1.status_code == 201
    assert res_ev2.status_code == 201

    ev1_sha = res_ev1.json()["sha256"]
    ev2_sha = res_ev2.json()["sha256"]

    # 3. Create run via POST /cases/{id}/runs
    res_run = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    assert res_run.status_code == 201
    run_data = res_run.json()
    run_id = run_data["run_id"]
    assert run_id.startswith("RUN-")
    assert run_data["claims_count"] > 0

    # 4. List runs for case
    res_runs = client.get(f"/cases/{case_id}/runs")
    assert res_runs.status_code == 200
    runs_list = res_runs.json()
    assert len(runs_list) == 1
    assert runs_list[0]["run_id"] == run_id

    # 5. Retrieve specific run
    res_single_run = client.get(f"/cases/{case_id}/runs/{run_id}")
    assert res_single_run.status_code == 200
    assert res_single_run.json()["engine_version"] == "pramana-engine@1.0.0"

    # 6. Retrieve claims in run
    res_claims = client.get(f"/cases/{case_id}/runs/{run_id}/claims")
    assert res_claims.status_code == 200
    claims = res_claims.json()
    assert len(claims) > 0

    # Look for promoted SAME_OBJECT_FLOW claim
    flow_claims = [c for c in claims if c["type"] == "SAME_OBJECT_FLOW"]
    assert len(flow_claims) == 1
    flow_claim = flow_claims[0]
    claim_id = flow_claim["claim_id"]
    assert flow_claim["grade"] in ("A", "B")
    assert flow_claim["status"] in ("CORROBORATED", "ASSERTED")

    # 7. Retrieve single claim by ID
    res_claim = client.get(f"/runs/{run_id}/claims/{claim_id}")
    assert res_claim.status_code == 200
    assert res_claim.json()["claim_id"] == claim_id

    # 8. Retrieve complete claim lineage
    res_lineage = client.get(f"/runs/{run_id}/claims/{claim_id}/lineage")
    assert res_lineage.status_code == 200
    lineage = res_lineage.json()
    assert lineage["claim"]["claim_id"] == claim_id
    assert len(lineage["events"]) == 2
    # Check that events resolve to evidence SHA-256
    shas = {e["evidence_sha256"] for e in lineage["events"]}
    assert ev1_sha in shas
    assert ev2_sha in shas

    # 9. Inspect correlation candidates
    res_corr = client.get(f"/cases/{case_id}/runs/{run_id}/correlations")
    assert res_corr.status_code == 200
    corr_data = res_corr.json()
    assert corr_data["promoted_count"] >= 1
    promoted = corr_data["promoted_relationships"]
    assert promoted[0]["candidate_type"] == "SAME_OBJECT_FLOW"
    assert "EXACT_FILE_KEY_MATCH" in promoted[0]["reason_codes"]

    # 10. Run/Case Ownership validation
    # Non-existent run
    assert client.get("/cases/CASE-API-LIFECYCLE/runs/RUN-DOES-NOT-EXIST").status_code == 404
    # Run in wrong case
    assert client.get(f"/cases/CASE-WRONG/runs/{run_id}").status_code == 404
    # Non-existent claim
    assert client.get(f"/runs/{run_id}/claims/CLAIM-DOES-NOT-EXIST").status_code == 404
    # Lineage for non-existent claim
    assert client.get(f"/runs/{run_id}/claims/CLAIM-DOES-NOT-EXIST/lineage").status_code == 404

    # 11. Immutability and run comparison on new analysis
    # Triggering another analysis run creates a new run without mutating the first
    res_run2 = client.post(f"/cases/{case_id}/runs", json={"engine_version": "pramana-engine@1.0.0"})
    assert res_run2.status_code == 201
    run_id_2 = res_run2.json()["run_id"]
    assert run_id_2 != run_id

    # Verify run 1 is unchanged
    res_run1_after = client.get(f"/cases/{case_id}/runs/{run_id}")
    assert res_run1_after.json()["run_id"] == run_id
    assert len(client.get(f"/cases/{case_id}/runs").json()) == 2
