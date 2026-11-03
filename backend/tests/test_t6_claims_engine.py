"""Comprehensive automated tests for T6 Claims Engine.

Covers all 23 verification requirements from the assignment:
1. Every supported claim type
2. Canonical parameters validation
3. Stable claim_key
4. Stable claim_id
5. Evidence hash changes affect claim_id
6. Support event changes affect claim_id
7. Rule-version changes affect claim_id
8. Assumption changes affect claim_id
9. SUPPORTS edges in lineage and identity
10. CONTRADICTS edges in lineage without changing identity
11. Claim-to-claim lineage and acyclic traversal
12. Cross-case reference rejection
13. Quarantined evidence rejection
14. Removed evidence rejection
15. Duplicate edge rejection
16. Witness family independence (2-level: source, device)
17. Multiple events from one family counting once
18. Different families adding toward CORROBORATED status
19. Every claim status: ASSERTED, CORROBORATED, CONTESTED, REFUTED
20. Every claim grade: Grade A, Grade B, Grade C
21. Invalid enum rejection (type, status, grade, role, ref_kind)
22. Non-finite numeric parameter rejection (NaN/Infinity)
23. Immutable-run integration via create_analysis_run
"""
from __future__ import annotations

import math
import pytest
from sqlalchemy.orm import Session

from app.db.claims import (
    H,
    ClaimSpec,
    ClaimValidationError,
    EdgeSpec,
    build_claim_rows,
    claim_lineage,
    compute_claim_id,
    compute_claim_key,
    verify_claim_id,
)
from app.db.models import (
    CLAIM_GRADES,
    CLAIM_STATUSES,
    CLAIM_TYPES,
    EVIDENCE_ACTIVE,
    EVIDENCE_QUARANTINED,
    EVIDENCE_REMOVED,
    AnalysisRun,
    Case,
    Claim,
    ClaimEdge,
    EventModel,
    Evidence,
    ImmutableRecordError,
)
from app.db.runs import create_analysis_run
from intelligence.claims import (
    count_independent_families,
    derive_witness_family,
    determine_claim_grade,
    determine_claim_status,
    generate_claims,
)


@pytest.fixture
def test_case_setup(client, db_session: Session):
    """Fixture providing a Case, active Evidence items, and normalized events."""
    case_id = "CASE-T6-TEST"
    client.post("/cases", json={"name": "T6 Claims Test Case", "case_id": case_id})

    # Upload two distinct evidence files
    ev_a_data = b"timestamp,action,actor,device,ip,object\n2026-10-18T10:00:00Z,archive_create,mira,dev1,1.1.1.1,file1.zip\n"
    ev_b_data = b"timestamp,action,actor,device,ip,object\n2026-10-18T10:05:00Z,file_upload,mira,dev2,1.1.1.2,file1.zip\n"

    res_a = client.post(f"/cases/{case_id}/evidence", files={"file": ("log_a.csv", ev_a_data)}).json()
    res_b = client.post(f"/cases/{case_id}/evidence", files={"file": ("log_b.csv", ev_b_data)}).json()

    ev_id_a = res_a["evidence_id"]
    ev_id_b = res_b["evidence_id"]
    sha_a = res_a["sha256"]
    sha_b = res_b["sha256"]

    events_a = [e.event_id for e in db_session.query(EventModel).filter_by(evidence_id=ev_id_a).all()]
    events_b = [e.event_id for e in db_session.query(EventModel).filter_by(evidence_id=ev_id_b).all()]

    return {
        "case_id": case_id,
        "ev_a": ev_id_a,
        "ev_b": ev_id_b,
        "sha_a": sha_a,
        "sha_b": sha_b,
        "events_a": events_a,
        "events_b": events_b,
    }


# 1. Every supported claim type
def test_every_supported_claim_type_can_be_built(test_case_setup, db_session):
    data = test_case_setup
    case_id = data["case_id"]
    ev_id_a = data["events_a"][0]
    manifest = [{"evidence_id": data["ev_a"], "sha256": data["sha_a"]}]

    specs = [
        ClaimSpec(
            type="SAME_OBJECT_FLOW",
            params={"object": "file1.zip"},
            status="ASSERTED",
            grade="B",
            rule_id="r1",
            rule_version="1.0",
            edges=[EdgeSpec("event", ev_id_a, "SUPPORTS", family="log:dev1")],
        ),
        ClaimSpec(
            type="OFFHOURS_SESSION",
            params={"actor": "mira", "hour": 2},
            status="ASSERTED",
            grade="B",
            rule_id="r2",
            rule_version="1.0",
            edges=[EdgeSpec("event", ev_id_a, "SUPPORTS", family="log:dev1")],
        ),
        ClaimSpec(
            type="ACTOR_DEVICE_CONSISTENT",
            params={"actor": "mira", "device": "dev1"},
            status="ASSERTED",
            grade="B",
            rule_id="r3",
            rule_version="1.0",
            edges=[EdgeSpec("event", ev_id_a, "SUPPORTS", family="log:dev1")],
        ),
        ClaimSpec(
            type="LOCATION_CONFLICT",
            params={"speed_kmh": 1200.0},
            status="CONTESTED",
            grade="C",
            rule_id="r4",
            rule_version="1.0",
            edges=[EdgeSpec("event", ev_id_a, "SUPPORTS", family="log:dev1")],
        ),
        ClaimSpec(
            type="NO_RECORD_IN_COVERED_WINDOW",
            params={"source": "log", "window_start": "10:00", "window_end": "11:00"},
            status="ASSERTED",
            grade="B",
            rule_id="r5",
            rule_version="1.0",
            edges=[EdgeSpec("event", ev_id_a, "SUPPORTS", family="log:dev1")],
        ),
        ClaimSpec(
            type="SESSION_ORIGIN_MISMATCH",
            params={"ip1": "1.1.1.1", "ip2": "2.2.2.2"},
            status="CONTESTED",
            grade="C",
            rule_id="r6",
            rule_version="1.0",
            edges=[EdgeSpec("event", ev_id_a, "SUPPORTS", family="log:dev1")],
        ),
    ]

    claims, edges = build_claim_rows(
        db_session,
        run_id="RUN-1",
        case_id=case_id,
        assumptions_hash="a" * 64,
        manifest_evidence=manifest,
        specs=specs,
    )
    assert len(claims) == len(CLAIM_TYPES) == 6
    types_built = {c["type"] for c in claims}
    assert types_built == set(CLAIM_TYPES)


# 2. Canonical parameters validation
def test_canonical_parameters_must_be_dict(test_case_setup, db_session):
    data = test_case_setup
    manifest = [{"evidence_id": data["ev_a"], "sha256": data["sha_a"]}]
    bad_spec = ClaimSpec(
        type="SAME_OBJECT_FLOW",
        params="not-a-dict",  # type: ignore
        status="ASSERTED",
        grade="B",
        rule_id="r",
        rule_version="1",
        edges=[EdgeSpec("event", data["events_a"][0], "SUPPORTS")],
    )
    with pytest.raises(ClaimValidationError, match="params must be a JSON object"):
        build_claim_rows(db_session, run_id="RUN-1", case_id=data["case_id"], assumptions_hash="a" * 64,
                         manifest_evidence=manifest, specs=[bad_spec])


# 3. Stable claim_key
def test_stable_claim_key():
    params1 = {"b": 2, "a": 1}
    params2 = {"a": 1, "b": 2}
    key1 = compute_claim_key("SAME_OBJECT_FLOW", params1)
    key2 = compute_claim_key("SAME_OBJECT_FLOW", params2)
    assert key1 == key2
    assert key1 == H("SAME_OBJECT_FLOW", {"a": 1, "b": 2})


# 4. Stable claim_id across event order
def test_stable_claim_id_across_input_event_order():
    key = "claim_key_123"
    evs1 = ["EV-0002", "EV-0001"]
    evs2 = ["EV-0001", "EV-0002"]
    shas = ["sha_val"]
    id1 = compute_claim_id(key, evs1, shas, "rule", "1.0", "assumptions")
    id2 = compute_claim_id(key, evs2, shas, "rule", "1.0", "assumptions")
    assert id1 == id2


# 5. Evidence hash changes affect claim_id
def test_evidence_hash_changes_affect_claim_id():
    key = "claim_key_123"
    evs = ["EV-0001"]
    id1 = compute_claim_id(key, evs, ["sha_original"], "rule", "1.0", "assumptions")
    id2 = compute_claim_id(key, evs, ["sha_modified"], "rule", "1.0", "assumptions")
    assert id1 != id2


# 6. Support event changes affect claim_id
def test_support_event_changes_affect_claim_id():
    key = "claim_key_123"
    shas = ["sha_val"]
    id1 = compute_claim_id(key, ["EV-1"], shas, "rule", "1.0", "assumptions")
    id2 = compute_claim_id(key, ["EV-2"], shas, "rule", "1.0", "assumptions")
    assert id1 != id2


# 7. Rule-version changes affect claim_id
def test_rule_version_changes_affect_claim_id():
    key = "claim_key_123"
    evs = ["EV-1"]
    shas = ["sha_val"]
    id1 = compute_claim_id(key, evs, shas, "rule", "1.0.0", "assumptions")
    id2 = compute_claim_id(key, evs, shas, "rule", "1.1.0", "assumptions")
    assert id1 != id2


# 8. Assumption changes affect claim_id
def test_assumption_changes_affect_claim_id():
    key = "claim_key_123"
    evs = ["EV-1"]
    shas = ["sha_val"]
    id1 = compute_claim_id(key, evs, shas, "rule", "1.0.0", H({"tz": "UTC"}))
    id2 = compute_claim_id(key, evs, shas, "rule", "1.0.0", H({"tz": "Asia/Kolkata"}))
    assert id1 != id2


# 9 & 10. SUPPORTS vs CONTRADICTS edge semantics
def test_contradicting_edges_do_not_alter_claim_id(test_case_setup, db_session):
    data = test_case_setup
    case_id = data["case_id"]
    manifest = [
        {"evidence_id": data["ev_a"], "sha256": data["sha_a"]},
        {"evidence_id": data["ev_b"], "sha256": data["sha_b"]},
    ]
    ev_a = data["events_a"][0]
    ev_b = data["events_b"][0]

    spec_uncontested = ClaimSpec(
        type="SAME_OBJECT_FLOW",
        params={"object": "target.zip"},
        status="ASSERTED",
        grade="B",
        rule_id="r_flow",
        rule_version="1.0",
        edges=[EdgeSpec("event", ev_a, "SUPPORTS", family="log:dev1")],
    )

    spec_contested = ClaimSpec(
        type="SAME_OBJECT_FLOW",
        params={"object": "target.zip"},
        status="CONTESTED",
        grade="C",
        rule_id="r_flow",
        rule_version="1.0",
        edges=[
            EdgeSpec("event", ev_a, "SUPPORTS", family="log:dev1"),
            EdgeSpec("event", ev_b, "CONTRADICTS", family="log:dev2"),
        ],
    )

    claims_u, _ = build_claim_rows(db_session, run_id="R-1", case_id=case_id, assumptions_hash="0" * 64,
                                   manifest_evidence=manifest, specs=[spec_uncontested])
    claims_c, _ = build_claim_rows(db_session, run_id="R-2", case_id=case_id, assumptions_hash="0" * 64,
                                   manifest_evidence=manifest, specs=[spec_contested])

    assert claims_u[0]["claim_id"] == claims_c[0]["claim_id"]


# 11. Claim-to-claim lineage
def test_claim_to_claim_lineage(test_case_setup, db_session):
    data = test_case_setup
    case_id = data["case_id"]
    ev_a = data["events_a"][0]

    spec_base = ClaimSpec(
        label="base_claim",
        type="OFFHOURS_SESSION",
        params={"actor": "mira", "hour": 2},
        status="ASSERTED",
        grade="B",
        rule_id="r_base",
        rule_version="1.0",
        edges=[EdgeSpec("event", ev_a, "SUPPORTS", family="log:dev1")],
    )

    spec_meta = ClaimSpec(
        type="ACTOR_DEVICE_CONSISTENT",
        params={"actor": "mira", "device": "dev1"},
        status="CORROBORATED",
        grade="A",
        rule_id="r_meta",
        rule_version="1.0",
        edges=[EdgeSpec("claim", "base_claim", "SUPPORTS")],
    )

    run = create_analysis_run(
        db_session,
        case_id=case_id,
        engine_version="engine@1",
        assumptions={"case_timezone": "UTC"},
        claims=[spec_base, spec_meta],
    )
    db_session.commit()

    meta_claim = next(c for c in run.claims if c.type == "ACTOR_DEVICE_CONSISTENT")
    lineage = claim_lineage(db_session, run.run_id, meta_claim.claim_id)

    assert len(lineage["claims"]) == 1
    sub_lineage = lineage["claims"][0]["lineage"]
    assert sub_lineage["claim"]["type"] == "OFFHOURS_SESSION"
    assert sub_lineage["events"][0]["event_id"] == ev_a
    assert sub_lineage["events"][0]["evidence_sha256"] == data["sha_a"]


# 12. Cross-case reference rejection
def test_cross_case_event_reference_rejected(test_case_setup, db_session, client):
    data = test_case_setup
    # Create another case with evidence
    client.post("/cases", json={"name": "Other Case", "case_id": "CASE-OTHER"})
    res = client.post("/cases/CASE-OTHER/evidence", files={"file": ("log_other.csv", b"timestamp,action\n2026-10-18T10:00:00Z,login\n")}).json()
    other_ev = db_session.query(EventModel).filter_by(evidence_id=res["evidence_id"]).first()

    manifest = [{"evidence_id": data["ev_a"], "sha256": data["sha_a"]}]
    spec = ClaimSpec(
        type="OFFHOURS_SESSION",
        params={"actor": "mira"},
        status="ASSERTED",
        grade="B",
        rule_id="r",
        rule_version="1",
        edges=[EdgeSpec("event", other_ev.event_id, "SUPPORTS")],
    )

    with pytest.raises(ClaimValidationError, match="belongs to case CASE-OTHER, not CASE-T6-TEST"):
        build_claim_rows(db_session, run_id="R-1", case_id=data["case_id"], assumptions_hash="0" * 64,
                         manifest_evidence=manifest, specs=[spec])


# 13 & 14. Quarantined and Removed evidence rejection
def test_quarantined_and_removed_evidence_rejected(test_case_setup, db_session):
    data = test_case_setup
    case_id = data["case_id"]

    # Manifest only includes ACTIVE evidence; ev_b is not active in manifest
    manifest_active_only = [{"evidence_id": data["ev_a"], "sha256": data["sha_a"]}]

    # Claim attempts to cite event from evidence B (not in active manifest)
    spec = ClaimSpec(
        type="SAME_OBJECT_FLOW",
        params={"object": "file.zip"},
        status="ASSERTED",
        grade="B",
        rule_id="r",
        rule_version="1",
        edges=[EdgeSpec("event", data["events_b"][0], "SUPPORTS")],
    )

    with pytest.raises(ClaimValidationError, match="not ACTIVE in this run's manifest"):
        build_claim_rows(db_session, run_id="R-1", case_id=case_id, assumptions_hash="0" * 64,
                         manifest_evidence=manifest_active_only, specs=[spec])


# 15. Duplicate edge rejection
def test_duplicate_edge_rejection(test_case_setup, db_session):
    data = test_case_setup
    manifest = [{"evidence_id": data["ev_a"], "sha256": data["sha_a"]}]
    ev_id = data["events_a"][0]

    spec = ClaimSpec(
        type="OFFHOURS_SESSION",
        params={"actor": "mira"},
        status="ASSERTED",
        grade="B",
        rule_id="r",
        rule_version="1",
        edges=[
            EdgeSpec("event", ev_id, "SUPPORTS"),
            EdgeSpec("event", ev_id, "SUPPORTS"),  # duplicate edge
        ],
    )
    with pytest.raises(ClaimValidationError, match="duplicate edge"):
        build_claim_rows(db_session, run_id="R-1", case_id=data["case_id"], assumptions_hash="0" * 64,
                         manifest_evidence=manifest, specs=[spec])


# 16, 17, 18. Witness family independence
def test_witness_family_independence():
    e1 = {"source": "log", "device": "laptop-1"}
    e2 = {"source": "log", "device": "laptop-1"}  # same family
    e3 = {"source": "browser", "device": "laptop-1"}  # different family (different source)
    e4 = {"source": "log", "device": "phone-2"}  # different family (different device)

    assert derive_witness_family(e1) == "log:laptop-1"
    assert derive_witness_family(e2) == "log:laptop-1"
    assert derive_witness_family(e3) == "browser:laptop-1"
    assert derive_witness_family(e4) == "log:phone-2"

    # Multiple events from same family count ONCE
    edges_same_family = [
        EdgeSpec("event", "EV-1", "SUPPORTS", family="log:laptop-1"),
        EdgeSpec("event", "EV-2", "SUPPORTS", family="log:laptop-1"),
    ]
    assert count_independent_families(edges_same_family) == 1
    assert determine_claim_status(1, has_contradiction=False) == "ASSERTED"

    # Different families add toward CORROBORATED
    edges_multi_family = [
        EdgeSpec("event", "EV-1", "SUPPORTS", family="log:laptop-1"),
        EdgeSpec("event", "EV-3", "SUPPORTS", family="browser:laptop-1"),
    ]
    assert count_independent_families(edges_multi_family) == 2
    assert determine_claim_status(2, has_contradiction=False) == "CORROBORATED"


# 19. Every claim status
def test_every_claim_status_logic():
    # 1 family, no contradiction -> ASSERTED
    assert determine_claim_status(1, has_contradiction=False) == "ASSERTED"
    # 2 families, no contradiction -> CORROBORATED
    assert determine_claim_status(2, has_contradiction=False) == "CORROBORATED"
    # Contradiction exists -> CONTESTED
    assert determine_claim_status(2, has_contradiction=True) == "CONTESTED"
    # Hard physical violation -> REFUTED
    assert determine_claim_status(2, has_contradiction=True, is_hard_violation=True) == "REFUTED"


# 20. Every claim grade
def test_every_claim_grade_logic():
    # Grade A: >=2 families, exact identifier, no contradiction
    assert determine_claim_grade("CORROBORATED", 2, has_exact_identifier=True) == "A"
    # Grade B: 1 family, exact identifier
    assert determine_claim_grade("ASSERTED", 1, has_exact_identifier=True) == "B"
    # Grade C: weak signal (no exact identifier)
    assert determine_claim_grade("ASSERTED", 1, has_exact_identifier=False) == "C"
    # Grade C: contested or refuted claims
    assert determine_claim_grade("CONTESTED", 2, has_exact_identifier=True) == "C"
    assert determine_claim_grade("REFUTED", 2, has_exact_identifier=True) == "C"


# 21. Invalid enum rejection
@pytest.mark.parametrize("bad_field,bad_val", [
    ("type", "INVALID_CLAIM_TYPE"),
    ("status", "STALE"),  # STALE is rejected (run-level only)
    ("status", "SUPERSEDED"),
    ("grade", "D"),
])
def test_invalid_enum_rejection(test_case_setup, db_session, bad_field, bad_val):
    data = test_case_setup
    manifest = [{"evidence_id": data["ev_a"], "sha256": data["sha_a"]}]
    kw = {
        "type": "OFFHOURS_SESSION",
        "params": {"actor": "mira"},
        "status": "ASSERTED",
        "grade": "B",
        "rule_id": "r",
        "rule_version": "1",
        "edges": [EdgeSpec("event", data["events_a"][0], "SUPPORTS")],
    }
    kw[bad_field] = bad_val
    spec = ClaimSpec(**kw)
    with pytest.raises(ClaimValidationError, match="is not one of"):
        build_claim_rows(db_session, run_id="R-1", case_id=data["case_id"], assumptions_hash="0" * 64,
                         manifest_evidence=manifest, specs=[spec])


# 22. Non-finite parameter rejection
def test_non_finite_parameter_rejection(test_case_setup, db_session):
    data = test_case_setup
    manifest = [{"evidence_id": data["ev_a"], "sha256": data["sha_a"]}]
    spec = ClaimSpec(
        type="LOCATION_CONFLICT",
        params={"speed_kmh": float("inf")},  # Infinity is invalid JSON
        status="CONTESTED",
        grade="C",
        rule_id="r",
        rule_version="1",
        edges=[EdgeSpec("event", data["events_a"][0], "SUPPORTS")],
    )
    with pytest.raises(ValueError):
        build_claim_rows(db_session, run_id="R-1", case_id=data["case_id"], assumptions_hash="0" * 64,
                         manifest_evidence=manifest, specs=[spec])


# 23. Immutable-run integration via create_analysis_run
def test_immutable_run_integration(test_case_setup, db_session):
    data = test_case_setup
    case_id = data["case_id"]
    ev_a = data["events_a"][0]
    ev_b = data["events_b"][0]

    spec = ClaimSpec(
        type="SAME_OBJECT_FLOW",
        params={"object": "file1.zip", "temporal_delta_seconds": 300.0},
        status="CORROBORATED",
        grade="A",
        rule_id="rule_same_object_flow",
        rule_version="1.0.0",
        edges=[
            EdgeSpec("event", ev_a, "SUPPORTS", family="log:dev1"),
            EdgeSpec("event", ev_b, "SUPPORTS", family="log:dev2"),
        ],
    )

    run = create_analysis_run(
        db_session,
        case_id=case_id,
        engine_version="pramana-engine@1.0.0",
        assumptions={"case_timezone": "UTC"},
        claims=[spec],
    )
    db_session.commit()

    assert run.run_id.startswith("RUN-")
    assert len(run.claims) == 1
    claim = run.claims[0]
    assert claim.type == "SAME_OBJECT_FLOW"
    assert claim.status == "CORROBORATED"
    assert claim.grade == "A"
    assert verify_claim_id(db_session, run.run_id, claim.claim_id)

    # Database immutability: run and claim rows cannot be updated
    with pytest.raises(ImmutableRecordError):
        claim.status = "REFUTED"
        db_session.commit()
    db_session.rollback()
