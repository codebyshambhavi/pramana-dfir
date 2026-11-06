"""Role 3 / Task 4: Provenance Chain and Lineage Integrity Tests.

Verifies:
1. Attempting to create a claim without supporting edges is rejected (unless ASSUMED).
2. Attempting to create an edge to a non-existent event is rejected.
3. Attempting to link an event with an invalid evidence hash is rejected.
4. Full provenance chain traversal: Hypothesis -> Claim -> Edge -> Event -> Evidence -> SHA-256.
"""
from __future__ import annotations

import re
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.db.claims import (
    ClaimSpec,
    ClaimValidationError,
    EdgeSpec,
    claim_lineage,
    compute_claim_key,
)
from app.db.models import AnalysisRun, Case, EventModel, Evidence
from app.db.runs import create_analysis_run, manifest_evidence
from app.services.runs import execute_analysis_run, get_run_details

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

CSV_DATA = (
    b"timestamp,action,actor,device,ip,object\n"
    b"2026-10-18T02:00:00Z,login,mira,dev-01,10.0.0.1,\n"
    b"2026-10-18T02:15:00Z,archive_create,mira,dev-01,10.0.0.1,secrets.tar.gz\n"
)


@pytest.fixture
def lineage_setup(client: TestClient, db_session: Session):
    case_id = "CASE-LINEAGE-INTEGRITY-TEST"
    client.post("/cases", json={"name": "Lineage Test", "case_id": case_id})
    res_ev = client.post(f"/cases/{case_id}/evidence", files={"file": ("sys.csv", CSV_DATA)})
    ev_id = res_ev.json()["evidence_id"]
    ev_sha = res_ev.json()["sha256"]

    events = db_session.query(EventModel).filter(EventModel.case_id == case_id).all()
    event_ids = [e.event_id for e in events]

    return case_id, ev_id, ev_sha, event_ids


def test_claim_without_supporting_edges_rejected(db_session: Session, lineage_setup):
    """Claim without any SUPPORTS edge must be rejected unless marked ASSUMED."""
    case_id, ev_id, ev_sha, event_ids = lineage_setup

    # 1. Zero edges with ASSERTED status -> rejected
    spec_no_edges = ClaimSpec(
        type="ACTOR_DEVICE_CONSISTENT",
        params={"actor": "mira", "device": "dev-01"},
        status="ASSERTED",
        grade="A",
        rule_id="RULE-1",
        rule_version="1.0",
        edges=[],
    )
    with pytest.raises(ClaimValidationError, match="backed by at least one ClaimEdge with role 'SUPPORTS'"):
        create_analysis_run(
            db_session,
            case_id=case_id,
            engine_version="pramana-engine@1.0.0",
            assumptions={"case_timezone": "UTC"},
            claims=[spec_no_edges],
        )

    # 2. Only CONTRADICTS edge with ASSERTED status -> rejected
    spec_only_contradicts = ClaimSpec(
        type="ACTOR_DEVICE_CONSISTENT",
        params={"actor": "mira", "device": "dev-01"},
        status="ASSERTED",
        grade="A",
        rule_id="RULE-1",
        rule_version="1.0",
        edges=[EdgeSpec(ref_kind="event", ref_id=event_ids[0], role="CONTRADICTS")],
    )
    with pytest.raises(ClaimValidationError, match="backed by at least one ClaimEdge with role 'SUPPORTS'"):
        create_analysis_run(
            db_session,
            case_id=case_id,
            engine_version="pramana-engine@1.0.0",
            assumptions={"case_timezone": "UTC"},
            claims=[spec_only_contradicts],
        )


def test_claim_with_assumed_status_without_edges_allowed(db_session: Session, lineage_setup):
    """Claim explicitly marked ASSUMED is permitted to have zero edges."""
    case_id, ev_id, ev_sha, event_ids = lineage_setup

    spec_assumed = ClaimSpec(
        type="ACTOR_DEVICE_CONSISTENT",
        params={"actor": "mira", "device": "dev-01"},
        status="ASSUMED",
        grade="C",
        rule_id="RULE-ASSUMPTION",
        rule_version="1.0",
        edges=[],
    )
    run = create_analysis_run(
        db_session,
        case_id=case_id,
        engine_version="pramana-engine@1.0.0",
        assumptions={"case_timezone": "UTC"},
        claims=[spec_assumed],
    )
    assert run is not None
    assert len(run.claims) == 1
    assert run.claims[0].status == "ASSUMED"


def test_edge_to_nonexistent_event_rejected(db_session: Session, lineage_setup):
    """Attempting to create an edge to a non-existent event must fail."""
    case_id, ev_id, ev_sha, event_ids = lineage_setup

    bad_spec = ClaimSpec(
        type="ACTOR_DEVICE_CONSISTENT",
        params={"actor": "mira", "device": "dev-01"},
        status="ASSERTED",
        grade="A",
        rule_id="RULE-1",
        rule_version="1.0",
        edges=[EdgeSpec(ref_kind="event", ref_id="NON_EXISTENT_EVENT_ID", role="SUPPORTS")],
    )
    with pytest.raises(ClaimValidationError, match="does not exist"):
        create_analysis_run(
            db_session,
            case_id=case_id,
            engine_version="pramana-engine@1.0.0",
            assumptions={"case_timezone": "UTC"},
            claims=[bad_spec],
        )


def test_edge_to_event_with_invalid_evidence_hash_rejected(db_session: Session, lineage_setup):
    """Attempting to link an event whose evidence has a malformed SHA-256 must fail."""
    case_id, ev_id, ev_sha, event_ids = lineage_setup

    spec = ClaimSpec(
        type="ACTOR_DEVICE_CONSISTENT",
        params={"actor": "mira", "device": "dev-01"},
        status="ASSERTED",
        grade="A",
        rule_id="RULE-1",
        rule_version="1.0",
        edges=[EdgeSpec(ref_kind="event", ref_id=event_ids[0], role="SUPPORTS")],
    )

    from app.db.claims import build_claim_rows
    with pytest.raises(ClaimValidationError, match="evidence intake SHA-256 .* is invalid"):
        build_claim_rows(
            db_session,
            run_id="RUN-TEST",
            case_id=case_id,
            assumptions_hash="a" * 64,
            manifest_evidence=[{"evidence_id": ev_id, "sha256": "INVALID_NON_HEX_SHA"}],
            specs=[spec],
        )


def test_full_provenance_chain_traversal(client: TestClient, db_session: Session, lineage_setup):
    """Verify unbroken provenance: Hypothesis -> Claim -> ClaimEdge -> Event -> Evidence -> SHA-256."""
    case_id, ev_id, ev_sha, event_ids = lineage_setup

    res = client.post(
        f"/cases/{case_id}/runs",
        json={"engine_version": "pramana-engine@1.0.0", "assumptions": {"case_timezone": "UTC"}},
    )
    assert res.status_code == 201
    run_data = res.json()
    run_id = run_data["run_id"]

    # 1. From top ranked hypothesis, get supporting claims
    top_hyp = run_data["ranked_hypotheses"][0]
    supporting_claims = top_hyp["supporting_claim_ids"]
    assert len(supporting_claims) > 0

    target_claim_id = supporting_claims[0]

    # 2. Query claim lineage endpoint: GET /runs/{run_id}/claims/{claim_id}/lineage
    lin_res = client.get(f"/runs/{run_id}/claims/{target_claim_id}/lineage")
    assert lin_res.status_code == 200
    lineage = lin_res.json()

    # 3. Verify Claim metadata
    assert lineage["claim"]["claim_id"] == target_claim_id
    assert lineage["claim"]["case_id"] == case_id

    # 4. Verify ClaimEdge -> Event -> Evidence -> SHA-256
    events = lineage["events"]
    assert len(events) > 0
    for edge_ev in events:
        assert edge_ev["role"] == "SUPPORTS"
        assert edge_ev["event_id"] in event_ids
        assert edge_ev["evidence_id"] == ev_id
        # Hash matches intake SHA-256 and is valid 64-char hex
        assert edge_ev["evidence_sha256"] == ev_sha
        assert _HEX64.match(edge_ev["evidence_sha256"]) is not None
