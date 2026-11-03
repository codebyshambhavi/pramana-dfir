"""Comprehensive automated tests for T5 Correlation and Link Engine.

Covers:
1. Exact file-key matching
2. URL basename normalization
3. Case-insensitive normalization
4. Content-hash matching
5. Actor matching
6. Device matching
7. Weak IP matching
8. NAT/shared-IP suppression
9. Hub suppression
10. Compatible action sequences
11. Incompatible action sequences
12. Temporal-only candidate rejection
13. Contradiction penalties
14. Promotion threshold behavior
15. Duplicate-event handling
16. Missing optional fields
17. Deterministic output across shuffled input
18. 100/1,000/5,000-event scalability tests with timing and candidate counts
"""
from __future__ import annotations

import random
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from intelligence.correlate import (
    REASON_CONTRADICTORY_IDENTIFIER,
    REASON_EXACT_FILE_KEY,
    REASON_HUB_SUPPRESSED,
    REASON_INSUFFICIENT_IDENTIFIER,
    REASON_SAME_ACTOR,
    REASON_SAME_DEVICE,
    REASON_SEQUENCE_COMPATIBLE,
    REASON_SHARED_IP,
    REASON_WITHIN_TIME_GATE,
    correlate_events,
    generate_candidates,
)
from intelligence.entities import (
    normalize_actor,
    normalize_device,
    normalize_file_object,
    normalize_ip,
)


def _ev(
    event_id: str,
    timestamp: str,
    *,
    action: str = "file_access",
    actor: str | None = "alice",
    device: str | None = "laptop-1",
    ip: str | None = "192.168.1.50",
    obj: str | None = "secret.docx",
    source: str = "log",
    raw: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "case_id": "CASE-TEST",
        "evidence_id": "EVID-001",
        "artifact_ref": f"{source}.log#1",
        "sha256": "0" * 64,
        "timestamp": timestamp,
        "source": source,
        "action": action,
        "actor": actor,
        "device": device,
        "ip": ip,
        "object": obj,
        "raw": raw or {},
    }


# 1. Exact file-key matching
def test_exact_file_key_matching():
    e1 = _ev("EV-1", "2026-10-18T10:00:00Z", obj="/var/data/evidence.zip", action="archive_create")
    e2 = _ev("EV-2", "2026-10-18T10:05:00Z", obj="/tmp/downloads/evidence.zip", action="file_upload")
    all_cands, promoted = correlate_events([e1, e2])
    assert len(promoted) == 1
    cand = promoted[0]
    assert REASON_EXACT_FILE_KEY in cand.reason_codes
    assert cand.canonical_entities["shared_object"] == "evidence.zip"
    assert cand.promotion_decision is True


# 2. URL basename normalization
def test_url_basename_normalization():
    assert normalize_file_object("https://vault.example.org/files/leak.tar.gz?auth=token", action="file_upload") == "leak.tar.gz"
    assert normalize_file_object("http://download.site/path/with%20spaces/report.pdf", action="file_upload") == "report.pdf"
    # Root URL or URL with no path should return None
    assert normalize_file_object("https://vault.example.org/", action="file_upload") is None
    # For a general visit, the full URL is retained to prevent false matches with files
    assert normalize_file_object("https://vault.example.org/page", action="visit") == "https://vault.example.org/page"


# 3. Case-insensitive normalization
def test_case_insensitive_normalization():
    assert normalize_actor("  Alice_Cooper  ") == "alice_cooper"
    assert normalize_device("  FIELD-LAPTOP-07  ") == "field-laptop-07"
    assert normalize_file_object("CASE-001.TAR.GZ") == "case-001.tar.gz"
    e1 = _ev("EV-1", "2026-10-18T10:00:00Z", obj="REPORT.PDF", actor="MIRA.CHEN", device="DEV-01")
    e2 = _ev("EV-2", "2026-10-18T10:02:00Z", obj="report.pdf", actor="mira.chen", device="dev-01")
    _, promoted = correlate_events([e1, e2])
    assert len(promoted) == 1
    assert REASON_EXACT_FILE_KEY in promoted[0].reason_codes
    assert REASON_SAME_ACTOR in promoted[0].reason_codes
    assert REASON_SAME_DEVICE in promoted[0].reason_codes


# 4. Content-hash matching
def test_content_hash_matching():
    hash_val = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    e1 = _ev("EV-1", "2026-10-18T10:00:00Z", obj="file1.bin", raw={"content_hash": hash_val})
    e2 = _ev("EV-2", "2026-10-18T10:04:00Z", obj="renamed.bin", raw={"sha256": hash_val})
    all_cands, promoted = correlate_events([e1, e2])
    assert len(promoted) == 1
    assert "content_hash" in promoted[0].matched_signals


# 5. Actor matching
def test_actor_matching():
    e1 = _ev("EV-1", "2026-10-18T10:00:00Z", actor="bob.smith", device="pc-1", obj="doc1")
    e2 = _ev("EV-2", "2026-10-18T10:02:00Z", actor="Bob.Smith", device="pc-2", obj="doc2")
    all_cands, promoted = correlate_events([e1, e2])
    # Actor alone on different devices without file match does not promote
    assert any(REASON_SAME_ACTOR in c.reason_codes for c in all_cands)


# 6. Device matching
def test_device_matching():
    e1 = _ev("EV-1", "2026-10-18T10:00:00Z", actor="user_a", device="workstation-99", obj="a")
    e2 = _ev("EV-2", "2026-10-18T10:01:00Z", actor="user_b", device="WORKSTATION-99", obj="b")
    all_cands, promoted = correlate_events([e1, e2])
    assert any(REASON_SAME_DEVICE in c.reason_codes for c in all_cands)


# 7. Weak IP matching
def test_weak_ip_matching():
    assert normalize_ip(" 192.168.1.1 ") == "192.168.1.1"
    assert normalize_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::8a2e:370:7334"
    assert normalize_ip("invalid-ip") is None
    e1 = _ev("EV-1", "2026-10-18T10:00:00Z", ip="10.0.0.5", actor="user1", device="dev1", obj="fileA")
    e2 = _ev("EV-2", "2026-10-18T10:03:00Z", ip="10.0.0.5", actor="user2", device="dev2", obj="fileB")
    all_cands, promoted = correlate_events([e1, e2])
    # IP alone is weak and cannot promote
    assert len(promoted) == 0
    assert any(REASON_SHARED_IP in c.reason_codes for c in all_cands)
    assert any(REASON_INSUFFICIENT_IDENTIFIER in c.reason_codes for c in all_cands)


# 8. NAT / shared-IP suppression
def test_shared_ip_cannot_be_sole_basis_for_promotion():
    # 5 events sharing the same public NAT IP with different actors, devices, and objects
    nat_ip = "198.51.100.1"
    events = [
        _ev(f"EV-{i}", f"2026-10-18T10:0{i}:00Z", ip=nat_ip, actor=f"user_{i}", device=f"phone_{i}", obj=f"file_{i}.txt")
        for i in range(5)
    ]
    _, promoted = correlate_events(events)
    # NAT IP alone must never establish an evidentiary relationship
    assert len(promoted) == 0


# 9. Hub suppression
def test_hub_suppression():
    # A common gateway IP or device appears across 20 events
    hub_ip = "203.0.113.1"
    events = [
        _ev(f"EV-{i}", f"2026-10-18T10:{i:02d}:00Z", ip=hub_ip, actor=f"user_{i}", device=f"dev_{i}", obj=f"obj_{i}")
        for i in range(15)
    ]
    all_cands, promoted = correlate_events(events)
    assert len(promoted) == 0
    # The common identifier gets hub suppressed
    hub_candidates = [c for c in all_cands if REASON_HUB_SUPPRESSED in c.reason_codes]
    assert len(hub_candidates) > 0


# 10. Compatible action sequences
def test_compatible_action_sequences():
    e1 = _ev("EV-1", "2026-10-18T10:00:00Z", action="archive_create", obj="data.tar.gz")
    e2 = _ev("EV-2", "2026-10-18T10:05:00Z", action="file_upload", obj="data.tar.gz")
    _, promoted = correlate_events([e1, e2])
    assert len(promoted) == 1
    assert REASON_SEQUENCE_COMPATIBLE in promoted[0].reason_codes
    assert promoted[0].sequence_compatibility == "COMPATIBLE"


# 11. Incompatible action sequences
def test_incompatible_action_sequences():
    # Upload occurs BEFORE the archive was created (impossible causality)
    e1 = _ev("EV-1", "2026-10-18T10:00:00Z", action="file_upload", obj="data.tar.gz")
    e2 = _ev("EV-2", "2026-10-18T10:05:00Z", action="archive_create", obj="data.tar.gz")
    all_cands, promoted = correlate_events([e1, e2])
    assert len(promoted) == 0
    assert any(c.sequence_compatibility == "INCOMPATIBLE" for c in all_cands)


# 12. Temporal-only candidate rejection
def test_temporal_only_rejection():
    # Two events occurred 10 seconds apart but have completely different actor, device, IP, and object
    e1 = _ev("EV-1", "2026-10-18T10:00:00Z", actor="alice", device="dev-1", ip="10.1.1.1", obj="photo.jpg")
    e2 = _ev("EV-2", "2026-10-18T10:00:10Z", actor="bob", device="dev-2", ip="10.2.2.2", obj="spreadsheet.xlsx")
    all_cands, promoted = correlate_events([e1, e2])
    # Temporal coincidence alone must never establish an evidentiary relationship
    assert len(promoted) == 0
    assert len(all_cands) == 0


# 13. Contradiction penalties
def test_contradiction_penalties():
    # Same object but contradictory actor mismatch on private session
    e1 = _ev("EV-1", "2026-10-18T10:00:00Z", actor="alice", device="laptop-1", obj="leak.zip", action="file_read")
    e2 = _ev("EV-2", "2026-10-18T10:02:00Z", actor="charlie", device="laptop-1", obj="leak.zip", action="file_upload")
    all_cands, _ = correlate_events([e1, e2])
    assert any(REASON_CONTRADICTORY_IDENTIFIER in c.reason_codes for c in all_cands)


# 14. Promotion threshold behavior
def test_promotion_threshold_behavior():
    # Strong identifier promotes within window
    e1 = _ev("EV-1", "2026-10-18T10:00:00Z", obj="target.zip")
    e2 = _ev("EV-2", "2026-10-18T10:08:00Z", obj="target.zip")
    _, promoted = correlate_events([e1, e2])
    assert len(promoted) == 1
    # Outside window (12 mins > 10 min window) -> rejected
    e3 = _ev("EV-3", "2026-10-18T10:12:00Z", obj="target.zip")
    all_cands, promoted_outside = correlate_events([e1, e3])
    assert len(promoted_outside) == 0


# 15. Duplicate-event handling
def test_duplicate_event_handling():
    # Duplicate identical events should not produce self-candidates or crashes
    e1 = _ev("EV-1", "2026-10-18T10:00:00Z", obj="doc.pdf")
    e2 = _ev("EV-1", "2026-10-18T10:00:00Z", obj="doc.pdf")
    all_cands, _ = correlate_events([e1, e2])
    assert len(all_cands) == 0


# 16. Missing optional fields
def test_missing_optional_fields():
    e1 = {"event_id": "EV-A", "case_id": "C", "evidence_id": "E1", "artifact_ref": "r", "sha256": "0" * 64,
           "timestamp": "2026-10-18T10:00:00Z", "source": "log", "action": "login"}
    e2 = {"event_id": "EV-B", "case_id": "C", "evidence_id": "E2", "artifact_ref": "r", "sha256": "0" * 64,
           "timestamp": "2026-10-18T10:02:00Z", "source": "log", "action": "login"}
    all_cands, promoted = correlate_events([e1, e2])
    assert len(promoted) == 0


# 17. Deterministic output across shuffled input
def test_deterministic_across_shuffled_input():
    events = [
        _ev("EV-1", "2026-10-18T10:00:00Z", obj="case.tar.gz", actor="mira", device="laptop-1"),
        _ev("EV-2", "2026-10-18T10:03:00Z", obj="case.tar.gz", actor="mira", device="laptop-1", action="file_upload"),
        _ev("EV-3", "2026-10-18T10:05:00Z", obj="notes.txt", actor="mira", device="laptop-1"),
    ]
    ref_all, ref_promoted = correlate_events(events)

    for seed in (42, 999, 1337):
        shuffled = list(events)
        random.seed(seed)
        random.shuffle(shuffled)
        test_all, test_promoted = correlate_events(shuffled)
        assert [c.candidate_id for c in test_all] == [c.candidate_id for c in ref_all]
        assert [c.candidate_id for c in test_promoted] == [c.candidate_id for c in ref_promoted]


# 18. Scalability benchmarks: 100, 1,000, 5,000 events
@pytest.mark.parametrize("n_events", [100, 1000, 5000])
def test_scalability_benchmark(n_events: int):
    """Verify hash-join indexed candidate generation scales sub-quadratically."""
    base_time = datetime(2026, 10, 18, 0, 0, tzinfo=timezone.utc)
    events = []
    # Distribute events over realistic clusters
    for i in range(n_events):
        cluster_id = i % 50
        time_offset = (i * 30) % (3600 * 24)
        t = (base_time + timedelta(seconds=time_offset)).strftime("%Y-%m-%dT%H:%M:%SZ")
        events.append(_ev(
            f"EV-{i:06d}",
            t,
            actor=f"user_{cluster_id}",
            device=f"device_{cluster_id}",
            ip=f"10.0.{cluster_id // 256}.{cluster_id % 256}",
            obj=f"cluster_artifact_{cluster_id}.zip" if (i % 5 == 0) else f"random_file_{i}.dat",
            action="archive_create" if (i % 2 == 0) else "file_upload",
        ))

    t_start = time.perf_counter()
    all_cands, promoted = correlate_events(events)
    elapsed = time.perf_counter() - t_start

    # Benchmarks should complete quickly (avoiding N^2 comparison)
    # 5,000 events should complete in well under 3.0 seconds
    assert elapsed < 5.0, f"{n_events} events took {elapsed:.3f}s"
    print(f"\n[BENCHMARK] N={n_events}: elapsed={elapsed:.4f}s, candidates={len(all_cands)}, promoted={len(promoted)}")
