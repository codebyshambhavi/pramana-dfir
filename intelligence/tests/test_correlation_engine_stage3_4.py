"""Stage 3/4 tests: field resolution, direct anchors, indexed candidates and scoring."""
from __future__ import annotations

import copy
from datetime import timedelta

import pytest

from intelligence.correlation.anchors import evaluate_anchor, evaluate_anchors, generate_candidate_pairs
from intelligence.correlation.fields import resolve_field
from intelligence.correlation.features import evaluate_parameter
from intelligence.correlation.registry import iter_fixtures, load_registry
from intelligence.correlation.scorer import score_pair
from intelligence.timeline import SourceClock

REGISTRY = load_registry()


def event(event_id="e1", **kwargs):
    base = {"event_id": event_id, "case_id": "case-1", "evidence_id": f"ev-{event_id}",
            "artifact_ref": f"artifact-{event_id}", "source": "log", "timestamp": "2026-11-24T10:00:00Z",
            "action": "login", "actor": "alice", "raw": {}}
    base.update(kwargs)
    return base


def test_field_resolver_reuses_entity_normalisers_and_locator():
    e = event(actor=" Alice   Smith ", raw={"src_ip": "2001:0db8::1", "tcp_dport": "8443"})
    f = resolve_field(e, "actor.normalized")
    assert f.value == "alice smith" and f.status == "PRESENT"
    assert f.source_locator == "artifact-e1#actor"
    assert resolve_field(e, "net.ip").value == ("2001:db8::1",)
    assert resolve_field(e, "net.dst_port").value == 8443


def test_placeholder_values_are_missing_and_invalid_ips_are_invalid():
    assert resolve_field(event(actor="unknown"), "actor.normalized").status == "MISSING"
    assert resolve_field(event(raw={"src_ip": "not-an-ip"}), "net.src_ip").status == "INVALID"


def test_actor_username_never_treats_ip_as_username():
    assert resolve_field(event(actor="203.0.113.8"), "actor.username").status == "MISSING"
    assert resolve_field(event(actor="alice@example.org"), "actor.username").value == "alice"


def test_real_zeek_dotted_keys_and_pcap_ports_resolve():
    zeek = event(source="zeek", raw={"id.orig_h": "10.0.0.5", "id.resp_h": "198.51.100.7",
                                      "id.orig_p": "51000", "id.resp_p": "8443", "uid": "C1"})
    assert resolve_field(zeek, "net.src_ip").value == "10.0.0.5"
    assert resolve_field(zeek, "net.dst_ip").value == "198.51.100.7"
    assert resolve_field(zeek, "net.dst_port").value == 8443
    pcap = event(source="pcap", raw={"src_ip": "10.0.0.5", "dst_ip": "198.51.100.7", "udp_dport": 53})
    assert resolve_field(pcap, "net.dst_port").value == 53


def test_sha256_anchor_is_primary_but_filename_never_is():
    h = "a" * 64
    a = event(source="gmail", integrity_status="UNVERIFIED", raw={"attachments": [{"filename": "report.pdf", "sha256": h}]})
    b = event("e2", source="log", integrity_status="UNVERIFIED", object=h)
    p = REGISTRY.get("ANCHOR_SHA256")
    result = evaluate_anchor(p, a, b)
    assert result.status == "ANCHORED"
    assert result.value_reference and len(result.value_reference) == 16
    assert h not in str(result.to_dict())  # value is not exposed in plaintext
    c = event("e3", source="log", integrity_status="UNVERIFIED", object="/tmp/report.pdf")
    assert evaluate_anchor(p, a, c).status == "NO_MATCH"


def test_bad_hash_length_is_not_a_sha256_anchor():
    a = event(integrity_status="UNVERIFIED", object="a" * 40); b = event("e2", integrity_status="UNVERIFIED", object="a" * 40)
    assert evaluate_anchor(REGISTRY.get("ANCHOR_SHA256"), a, b).status != "ANCHORED"


def test_blocked_integrity_rejects_direct_anchor():
    h = "b" * 64
    a = event(integrity_status="MISMATCH", object=h); b = event("e2", object=h)
    assert evaluate_anchor(REGISTRY.get("ANCHOR_SHA256"), a, b).status == "REJECTED"


def test_thread_anchor_requires_account_scope():
    a = event(source="gmail", integrity_status="UNVERIFIED", thread_id="t-1", account_id="acct-a")
    b = event("e2", source="gmail", integrity_status="UNVERIFIED", thread_id="t-1", account_id="acct-b")
    assert evaluate_anchor(REGISTRY.get("ANCHOR_THREAD_ID"), a, b).status == "REJECTED"


def test_filename_ip_and_timestamp_do_not_create_primary_anchors():
    a = event(source="log", object="same.pdf", ip="203.0.113.1")
    b = event("e2", source="pcap", object="same.pdf", ip="203.0.113.1", timestamp="2026-11-24T10:00:01Z")
    assert all(r.status != "ANCHORED" for r in evaluate_anchors(a, b, REGISTRY))


def test_candidate_generation_is_indexed_bounded_and_case_scoped():
    h = "c" * 64
    events = [event("a", object=h), event("b", source="gmail", object=h),
              event("x", case_id="case-2", object=h)]
    pairs, meta = generate_candidate_pairs(events, REGISTRY)
    assert [(x[0]["event_id"], x[1]["event_id"]) for x in pairs] == [("a", "b")]
    assert meta["candidate_pair_count"] == 1


def test_candidate_generation_records_skipped_hub_buckets():
    events = [event(str(i), ip="203.0.113.10") for i in range(5)]
    _, meta = generate_candidate_pairs(events, REGISTRY, max_bucket_size=2)
    assert any(x["reason"] == "MAX_BUCKET_SIZE" for x in meta["skipped_buckets"])


def _fixture_events(fx):
    out=[]
    for i, original in enumerate(fx["events"]):
        e=copy.deepcopy(original)
        e.setdefault("event_id",f"fixture-{i}"); e.setdefault("case_id","fixture-case")
        e.setdefault("evidence_id",f"fixture-evidence-{i}"); e.setdefault("artifact_ref",f"fixture-artifact-{i}")
        e.setdefault("sha256",None); e.setdefault("parser_version","fixture-parser")
        e.setdefault("tz_assumption","explicit_offset"); e.setdefault("family","fixture")
        out.append(e)
    clocks={s:SourceClock(timedelta(seconds=v.get("offset_seconds",0)),timedelta(seconds=v.get("uncertainty_seconds",0)))
            for s,v in fx.get("source_clocks",{}).items()}
    return out,clocks


@pytest.mark.parametrize("parameter_id,kind", [(p.parameter_id,k) for p,k,_ in iter_fixtures(REGISTRY)])
def test_every_registry_fixture_executes_against_real_resolver(parameter_id, kind):
    p=REGISTRY.get(parameter_id); fx=p.spec["fixtures"][kind]
    events,clocks=_fixture_events(fx)
    if p.role == "ANCHOR":
        ctx={e["evidence_id"]:{"status":"ACTIVE","verify_state":None} for e in events}
        actual=evaluate_anchor(p,*events,evidence_context=ctx).status
        assert actual == fx["expect"]["status"], (parameter_id,kind,fx["label"],actual)
    else:
        signal=evaluate_parameter(p,*events,registry=REGISTRY,clocks=clocks,reference_data=fx.get("reference_data"))
        expected=fx["expect"]
        if "status" in expected: assert signal.status == expected["status"], (parameter_id,kind,fx["label"])
        if "value" in expected: assert signal.value == pytest.approx(expected["value"],abs=1e-6), (parameter_id,kind,fx["label"],signal)
        if "min" in expected: assert signal.value is not None and signal.value >= expected["min"]
        if "max" in expected: assert signal.value is not None and signal.value <= expected["max"]


def test_shared_ip_and_time_alone_stay_below_review_threshold():
    a=event(source="log", actor=None, action="observation", ip="203.0.113.7")
    b=event("e2", source="pcap", actor=None, action="observation", ip="203.0.113.7", timestamp="2026-11-24T10:01:00Z")
    result=score_pair(a,b,REGISTRY,events=[a,b],clocks={})
    assert result["score"] < REGISTRY.t_review


def test_secondary_score_is_deterministic_and_exposes_contributions():
    a=event(source="gmail", actor="Alice <alice@example.org>", account_id="acct-1",
            raw={"sender":"Alice <alice@example.org>","subject":"Project Orion status","body":"alpha beta gamma delta"})
    b=event("e2",source="outlook",actor="Alice <alice@example.org>",account_id="acct-1",
            raw={"sender":"Alice <alice@example.org>","subject":"Project Orion status","body":"alpha beta gamma delta"})
    first=score_pair(a,b,REGISTRY,events=[a,b]); second=score_pair(a,b,REGISTRY,events=[a,b])
    assert first == second
    assert first["feature_contributions"]
    assert first["registry_hash"] == REGISTRY.registry_hash
    assert first["thresholds"]["status"] == "PROVISIONAL"


def test_account_plus_time_lands_in_provisional_review_band():
    a=event(source="log",actor=None,account_id="acct-7",parser_confidence=1.0,acquisition_method="vendor_export",integrity_status="MATCH")
    b=event("e2",source="log",actor=None,account_id="acct-7",parser_confidence=1.0,acquisition_method="vendor_export",integrity_status="MATCH",timestamp="2026-11-24T10:02:00Z")
    result=score_pair(a,b,REGISTRY,events=[a,b])
    assert REGISTRY.t_review <= result["score"] < REGISTRY.t_high
    assert result["status"] == "ANALYST_REVIEW"


def test_email_time_order_and_domain_signals_can_reach_high_band():
    a=event(source="gmail",action="dns_query",actor="Alice <alice@example.org>",parser_confidence=1.0,
            acquisition_method="vendor_export",integrity_status="MATCH",
            raw={"sender":"Alice <alice@example.org>","body":"Please review https://vault.example.org"})
    b=event("e2",source="zeek",action="network_connection",actor="Alice <alice@example.org>",parser_confidence=1.0,
            acquisition_method="vendor_export",integrity_status="MATCH",timestamp="2026-11-24T10:01:00Z",
            raw={"query":"vault.example.org","uid":"C-7"})
    result=score_pair(a,b,REGISTRY,events=[a,b])
    assert result["score"] >= REGISTRY.t_high
    assert result["status"] == "HIGH_CONFIDENCE"


def test_common_value_collision_is_a_separate_negative_contribution():
    a=event(source="gmail",actor="Alice <alice@example.org>",raw={"subject":"hello"},parser_confidence=1.0)
    b=event("e2",source="gmail",actor="Alice <alice@example.org>",raw={"subject":"hello"},parser_confidence=1.0)
    result=score_pair(a,b,REGISTRY,events=[a,b])
    lines=[x for x in result["feature_contributions"] if x["kind"]=="collision_penalty"]
    assert lines
    assert all(x["amount"] < 0 for x in lines)


def test_candidate_bucket_limits_are_applied_per_case_not_across_cases():
    shared = "d" * 64
    events = [
        event("a1", case_id="case-a", object=shared, timestamp=None),
        event("a2", case_id="case-a", object=shared, timestamp=None),
        event("b1", case_id="case-b", object=shared, timestamp=None),
        event("b2", case_id="case-b", object=shared, timestamp=None),
        event("b3", case_id="case-b", object=shared, timestamp=None),
    ]
    pairs, meta = generate_candidate_pairs(events, REGISTRY, max_bucket_size=2)
    actual = {(x[0]["case_id"], x[1]["case_id"]) for x in pairs}
    assert actual == {("case-a", "case-a")}
    assert any(x["case_id"] == "case-b" and x["reason"] == "MAX_BUCKET_SIZE" for x in meta["skipped_buckets"])
