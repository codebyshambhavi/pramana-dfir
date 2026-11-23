"""ROLE 2 integration coverage for the complete evidence-tamper lifecycle.

This exercises the public demo endpoint and verifies invalidation against the
run-A claim/evidence lineage, rather than treating the engine's own diff output
as the oracle.
"""
from __future__ import annotations

import io

from fastapi.testclient import TestClient


LOG_EVIDENCE = (
    b"timestamp,action,actor,device,ip,object\n"
    b"2026-10-18T02:00:00Z,login,mira,dev-01,10.0.0.1,\n"
    b"2026-10-18T02:15:00Z,archive_create,mira,dev-01,10.0.0.1,exfil.tar.gz\n"
)

BROWSER_EVIDENCE = (
    b"timestamp,action,url,actor,device,ip\n"
    b"2026-10-18T02:20:00Z,upload,https://vault.external/upload/exfil.tar.gz,mira,dev-01,10.0.0.1\n"
)


def test_demo_tamper_quarantines_evidence_invalidates_run_and_supports_child_diff(
    client: TestClient,
    monkeypatch,
):
    monkeypatch.setenv("DEMO_MODE", "1")
    case_id = "CASE-T10-TAMPER-LIFECYCLE"

    created = client.post("/cases", json={"name": "T10 Tamper Lifecycle", "case_id": case_id})
    assert created.status_code == 201

    uploaded_log = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("system.csv", io.BytesIO(LOG_EVIDENCE), "text/csv")},
    )
    uploaded_browser = client.post(
        f"/cases/{case_id}/evidence",
        files={"file": ("browser.csv", io.BytesIO(BROWSER_EVIDENCE), "text/csv")},
    )
    assert uploaded_log.status_code == 201
    assert uploaded_browser.status_code == 201
    browser_id = uploaded_browser.json()["evidence_id"]

    # Baseline integrity must match before the first analysis.
    initial_verify = client.post(f"/evidence/{browser_id}/verify")
    assert initial_verify.status_code == 200
    assert initial_verify.json()["verify_state"] == "MATCH"

    run_a_response = client.post(
        f"/cases/{case_id}/runs",
        json={"assumptions": {"case_timezone": "UTC"}},
    )
    assert run_a_response.status_code == 201, run_a_response.text
    run_a_id = run_a_response.json()["run_id"]

    run_a_details = client.get(f"/runs/{run_a_id}")
    assert run_a_details.status_code == 200
    run_a = run_a_details.json()

    # Independent oracle: identify Run A claims with event lineage into the
    # evidence item that will be tampered with.
    events_response = client.get(f"/cases/{case_id}/events")
    assert events_response.status_code == 200
    event_to_evidence = {
        event["event_id"]: event["evidence_id"]
        for event in events_response.json()
    }
    expected_invalidated_claim_keys = {
        claim["claim_key"]
        for claim in run_a["claims"]
        if any(
            edge.get("ref_kind") == "event"
            and event_to_evidence.get(edge.get("ref_id")) == browser_id
            for edge in claim.get("edges", [])
        )
    }
    assert expected_invalidated_claim_keys, "fixture must create claims linked to browser evidence"

    tamper_response = client.post(f"/evidence/{browser_id}/simulate-tamper")
    assert tamper_response.status_code == 200, tamper_response.text
    assert tamper_response.json()["status"] == "ACTIVE"

    quarantined = client.post(f"/evidence/{browser_id}/verify")
    assert quarantined.status_code == 200
    assert quarantined.json()["verify_state"] == "MISMATCH"
    assert quarantined.json()["status"] == "QUARANTINED"

    invalidated_run_a = client.get(f"/runs/{run_a_id}")
    assert invalidated_run_a.status_code == 200
    assert invalidated_run_a.json()["validity"] == "INVALIDATED"

    run_b_response = client.post(
        f"/cases/{case_id}/runs",
        json={
            "assumptions": {"case_timezone": "UTC"},
            "parent_run_id": run_a_id,
        },
    )
    assert run_b_response.status_code == 201, run_b_response.text
    run_b_id = run_b_response.json()["run_id"]
    assert run_b_response.json()["parent_run_id"] == run_a_id

    diff_response = client.get(f"/runs/{run_a_id}/diff/{run_b_id}")
    assert diff_response.status_code == 200, diff_response.text
    diff = diff_response.json()
    assert any(item["evidence_id"] == browser_id for item in diff["evidence_diff"]["removed"])

    actual_removed_claim_keys = {
        claim["claim_key"] for claim in diff["claims_diff"]["removed_claims"]
    }
    assert expected_invalidated_claim_keys <= actual_removed_claim_keys
