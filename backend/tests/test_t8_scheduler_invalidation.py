"""Role 3 / Task 5: End-to-End Scheduler-Log Invalidation and Run Diffing Scenario.

Scenario:
1. Incident window at ~03:00 UTC.
2. Ingest evidence including scheduler_log.csv covering 02:00 to 04:00 UTC.
3. Run 1: scheduler log demonstrably covers window but lacks scheduled backup task.
   H2-EXP-2 evaluates to MISSING, penalizing H2 (Sanctioned Backup).
4. Evidence verification failure / quarantine of scheduler_log.csv.
5. Run 1 validity transitions to INVALIDATED.
6. Run 2 (child run of Run 1): scheduler log is excluded from active evidence manifest.
   H2-EXP-2 transitions from MISSING to UNOBSERVABLE, incurring 0.0 penalty.
7. Run diff (GET /runs/{run_1}/diff/{run_2}) confirms:
   - Manifest diff records scheduler log removal.
   - H2 inconsistency score improves (decreases by 0.5).
   - Item state shift from MISSING to UNOBSERVABLE is explicitly detailed.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

SYSTEM_LOG = (
    b"timestamp,action,actor,device,ip,object\n"
    b"2026-10-18T02:50:00Z,login,backup-svc,srv-01,10.0.0.1,\n"
    b"2026-10-18T03:00:00Z,archive_create,backup-svc,srv-01,10.0.0.1,daily_backup.tar.gz\n"
)

BROWSER_LOG = (
    b"timestamp,action,url,actor,device,ip\n"
    b"2026-10-18T03:05:00Z,upload,https://backup-vault.internal/store/daily_backup.tar.gz,backup-svc,srv-01,10.0.0.1\n"
)

# Scheduler log covers the window from 02:00 to 04:00, but has NO scheduled backup task
SCHEDULER_LOG = (
    b"timestamp,action,actor,device,object\n"
    b"2026-10-18T02:00:00Z,job_start,root,srv-01,sys_cleanup\n"
    b"2026-10-18T04:00:00Z,job_start,root,srv-01,log_rotation\n"
)


def test_scheduler_log_quarantine_invalidation_end_to_end(client: TestClient):
    case_id = "CASE-SCHEDULER-INVALIDATION-E2E"
    client.post("/cases", json={"name": "Scheduler Invalidation Case", "case_id": case_id})

    # Step 1: Ingest evidence: system log, browser log, and scheduler log
    res_sys = client.post(f"/cases/{case_id}/evidence", files={"file": ("sys.csv", SYSTEM_LOG)})
    res_brw = client.post(f"/cases/{case_id}/evidence", files={"file": ("browser.csv", BROWSER_LOG)})
    res_sch = client.post(f"/cases/{case_id}/evidence", files={"file": ("scheduler_tasks.csv", SCHEDULER_LOG)})

    assert res_sys.status_code == 201
    assert res_brw.status_code == 201
    assert res_sch.status_code == 201

    sys_id = res_sys.json()["evidence_id"]
    brw_id = res_brw.json()["evidence_id"]
    sch_id = res_sch.json()["evidence_id"]

    # Step 2: Initial Run 1
    # Scheduler covers the window -> H2 expected backup record is MISSING -> penalizes H2
    res_run1 = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    assert res_run1.status_code == 201
    run1 = res_run1.json()
    run1_id = run1["run_id"]

    h2_run1 = next(h for h in run1["ranked_hypotheses"] if h["id"] == "H2")
    exp2_run1 = next(e for e in h2_run1["evaluations"] if e["item_id"] == "H2-EXP-2")
    # Scheduler is demonstrably covered, so expected backup task is MISSING
    assert exp2_run1["state"] == "MISSING"
    assert exp2_run1["disconfirmation_penalty"] == 0.5
    h2_run1_score = h2_run1["inconsistency_score"]
    assert h2_run1_score >= 0.5

    # Step 3: Quarantine / remove scheduler log due to verification failure or custody break
    rem_res = client.post(
        f"/evidence/{sch_id}/remove",
        json={"actor": "Forensic Auditor", "reason": "Scheduler log integrity failure / clock tampering"},
    )
    assert rem_res.status_code == 200
    assert rem_res.json()["status"] == "REMOVED"

    # Step 4: Run 1 validity is now INVALIDATED
    run1_details = client.get(f"/runs/{run1_id}").json()
    assert run1_details["is_valid"] is False
    assert run1_details["validity"] == "INVALIDATED"
    assert any(sch_id in r for r in run1_details["invalidation_reasons"])

    # Step 5: Execute Run 2 referencing Run 1 as parent
    # Active manifest now excludes scheduler log
    res_run2 = client.post(
        f"/cases/{case_id}/runs",
        json={
            "engine_version": "pramana-engine@1.0.0",
            "assumptions": {"case_timezone": "UTC"},
            "parent_run_id": run1_id,
        },
    )
    assert res_run2.status_code == 201
    run2 = res_run2.json()
    run2_id = run2["run_id"]

    # In Run 2, scheduler source is unmonitored / unobserved -> H2-EXP-2 is UNOBSERVABLE
    h2_run2 = next(h for h in run2["ranked_hypotheses"] if h["id"] == "H2")
    exp2_run2 = next(e for e in h2_run2["evaluations"] if e["item_id"] == "H2-EXP-2")
    assert exp2_run2["state"] == "UNOBSERVABLE"
    assert exp2_run2["disconfirmation_penalty"] == 0.0

    # H2 is relatively stronger / less disconfirmed in Run 2
    assert h2_run2["inconsistency_score"] < h2_run1_score

    # Step 6: Diff Run 1 and Run 2 (GET /runs/{run1_id}/diff/{run2_id})
    diff_res = client.get(f"/runs/{run1_id}/diff/{run2_id}")
    assert diff_res.status_code == 200
    diff = diff_res.json()

    # Verify manifest diff records scheduler evidence removal
    removed_evidence_ids = [e["evidence_id"] for e in diff["evidence_diff"]["removed"]]
    assert sch_id in removed_evidence_ids

    # Verify H2 score improvement is recorded in hypothesis diff
    h2_diff = next(d for d in diff["hypothesis_diffs"] if d["hypothesis_id"] == "H2")
    assert h2_diff["old_score"] > h2_diff["new_score"]
    assert h2_diff["score_delta"] < 0.0

    # Verify item state shift from MISSING to UNOBSERVABLE
    h2_item_shifts = h2_diff.get("item_state_shifts", [])
    exp2_shift = next((s for s in h2_item_shifts if s["item_id"] == "H2-EXP-2"), None)
    assert exp2_shift is not None
    assert exp2_shift["old_state"] == "MISSING"
    assert exp2_shift["new_state"] == "UNOBSERVABLE"
    assert exp2_shift["old_penalty"] == 0.5
    assert exp2_shift["new_penalty"] == 0.0

    # Verify root cause notes explain the shift
    assert any("H2-EXP-2 shifted from MISSING to UNOBSERVABLE" in note for note in diff["root_cause_notes"])
    assert "H2-EXP-2 shifted from MISSING to UNOBSERVABLE" in diff["root_cause_analysis"]
