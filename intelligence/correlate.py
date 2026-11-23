"""Role 3 / T5: Deterministic evidence correlation and link engine.

Discovers relationships between heterogeneous digital forensic events using
multi-signal evaluation, indexed candidate generation, sequence compatibility,
and hub suppression.

Architecture:
- Entity normalization via intelligence.entities
- Hash-join / indexed candidate generation (avoids unrestricted O(n²) comparison)
- Multi-signal scoring (exact file key, content hash, shared device, actor, IP)
- Action sequence compatibility (e.g. archive_create -> file_upload)
- Deterministic hub suppression (discounting high-frequency infrastructure)
- Transparent reason codes and human-auditable explanations
- Promoted links become SAME_OBJECT_FLOW claims in T6
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Mapping, Sequence

from . import common
from .config import ARCHIVE_UPLOAD_WINDOW, DEFAULT_CORRELATION_WINDOW
from .entities import (
    CanonicalEntities,
    extract_canonical_entities,
    normalize_actor,
    normalize_device,
    normalize_file_object,
    normalize_ip,
)
from .timeline import TimeInterval, SourceClock, effective_interval, event_interval, load_source_clocks

# ---------------------------------------------------------------------------
# Reason codes (contracted set)
# ---------------------------------------------------------------------------
REASON_EXACT_FILE_KEY = "EXACT_FILE_KEY_MATCH"
REASON_CONTENT_HASH = "CONTENT_HASH_MATCH"
REASON_SAME_DEVICE = "SAME_DEVICE"
REASON_SAME_ACTOR = "SAME_ACTOR"
REASON_SHARED_IP = "SHARED_IP_WEAK_SIGNAL"
REASON_SEQUENCE_COMPATIBLE = "ACTION_SEQUENCE_COMPATIBLE"
REASON_WITHIN_TIME_GATE = "WITHIN_TIME_GATE"
REASON_HUB_SUPPRESSED = "HUB_SUPPRESSED"
REASON_CONTRADICTORY_IDENTIFIER = "CONTRADICTORY_IDENTIFIER"
REASON_INSUFFICIENT_IDENTIFIER = "INSUFFICIENT_IDENTIFIER_SIGNAL"
REASON_TEMPORAL_ONLY_REJECTED = "TEMPORAL_ONLY_REJECTED"

ALL_REASON_CODES = frozenset({
    REASON_EXACT_FILE_KEY,
    REASON_CONTENT_HASH,
    REASON_SAME_DEVICE,
    REASON_SAME_ACTOR,
    REASON_SHARED_IP,
    REASON_SEQUENCE_COMPATIBLE,
    REASON_WITHIN_TIME_GATE,
    REASON_HUB_SUPPRESSED,
    REASON_CONTRADICTORY_IDENTIFIER,
    REASON_INSUFFICIENT_IDENTIFIER,
    REASON_TEMPORAL_ONLY_REJECTED,
})

# Hub thresholds: identifiers with count exceeding these are discounted
IP_HUB_THRESHOLD = 3
DEVICE_HUB_THRESHOLD = 8


@dataclass(frozen=True)
class CandidateRelationship:
    """Structured candidate relationship output from T5."""

    candidate_id: str
    source_event_id: str
    target_event_id: str
    candidate_type: str
    matched_signals: list[str]
    canonical_entities: dict[str, Any]
    temporal_delta: float  # seconds
    sequence_compatibility: str  # "COMPATIBLE", "INCOMPATIBLE", "NEUTRAL"
    contradiction_signals: list[str]
    score: float  # internal ranking score, never a guilt probability
    promotion_decision: bool
    reason_codes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "source_event_id": self.source_event_id,
            "target_event_id": self.target_event_id,
            "candidate_type": self.candidate_type,
            "matched_signals": self.matched_signals,
            "canonical_entities": self.canonical_entities,
            "temporal_delta": self.temporal_delta,
            "sequence_compatibility": self.sequence_compatibility,
            "contradiction_signals": self.contradiction_signals,
            "score": self.score,
            "promotion_decision": self.promotion_decision,
            "reason_codes": self.reason_codes,
        }


def _compute_candidate_id(e1_id: str, e2_id: str, candidate_type: str, disambiguator: str = "") -> str:
    """Deterministic, content-addressed candidate identifier."""
    payload = f"{min(e1_id, e2_id)}|{max(e1_id, e2_id)}|{candidate_type}|{disambiguator}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return f"CAND-{digest}"


def _hub_factor(count: int, threshold: int) -> float:
    """Deterministic formula for discounting common infrastructure identifiers.

    factor = 1.0 / (1.0 + log2(1 + count - threshold)) if count > threshold else 1.0
    """
    if count <= threshold:
        return 1.0
    excess = count - threshold
    return 1.0 / (1.0 + math.log2(1.0 + excess))


def _interval_separation_seconds(iv1: TimeInterval, iv2: TimeInterval) -> float:
    """Evaluate temporal separation between two effective intervals.

    Returns:
        0.0 if the intervals overlap or touch.
        Positive seconds between the nearer boundaries if strictly separated.
    """
    if iv1.overlaps(iv2):
        return 0.0
    if iv1.hi < iv2.lo:
        return (iv2.lo - iv1.hi).total_seconds()
    return (iv1.lo - iv2.hi).total_seconds()


def _check_sequence_compatibility(
    action1: str, action2: str, dt1: datetime, dt2: datetime
) -> tuple[str, bool]:
    """Evaluate operational/causal sequence compatibility.

    Returns:
        (sequence_status, is_compatible_boost)
        where sequence_status in ("COMPATIBLE", "INCOMPATIBLE", "NEUTRAL")
    """
    # Canonical actions
    a1 = (action1 or "").lower()
    a2 = (action2 or "").lower()

    # Ordered pairs: (earlier_action, later_action)
    ORDERED_PAIRS = {
        ("archive_create", "file_upload"),
        ("file_read", "archive_create"),
        ("file_open", "archive_create"),
        ("file_access", "archive_create"),
        ("login", "archive_create"),
        ("login", "file_upload"),
        ("login", "file_access"),
        ("session_start", "file_upload"),
        ("session_start", "file_access"),
        ("message_sent", "archive_create"),
        ("message_sent", "file_access"),
        ("message_sent", "file_upload"),
        ("file_upload", "message_sent"),
        ("file_download", "file_open"),
    }

    if (a1, a2) in ORDERED_PAIRS:
        # e1 should occur before or at e2
        if dt1 <= dt2:
            return "COMPATIBLE", True
        else:
            return "INCOMPATIBLE", False

    if (a2, a1) in ORDERED_PAIRS:
        # e2 should occur before e1
        if dt2 <= dt1:
            return "COMPATIBLE", True
        else:
            return "INCOMPATIBLE", False

    return "NEUTRAL", False


def generate_candidates(
    events: Sequence[Mapping[str, Any] | common.NormalizedEvent],
    *,
    max_window: timedelta | None = None,
    source_clocks: Mapping[str, SourceClock] | None = None,
) -> tuple[list[CandidateRelationship], list[CandidateRelationship]]:
    """Indexed candidate generation and relationship promotion.

    Args:
        events: Event dictionaries or NormalizedEvent instances.
        max_window: Override the maximum correlation window.
        source_clocks: Per-source clock offset/uncertainty mapping (T2).  When
            ``None`` the clocks are loaded from the environment variable
            ``PRAMANA_SOURCE_CLOCKS`` (same as ``timeline.load_source_clocks``).
            Pass an empty dict ``{}`` to disable clock correction in tests.

    Returns:
        (all_candidates, promoted_relationships)
    """
    if len(events) < 2:
        return [], []

    # Resolve source clocks once (T2 effective-interval support)
    clocks: Mapping[str, SourceClock] = (
        source_clocks if source_clocks is not None else load_source_clocks()
    )

    # 1. Normalize events and extract canonical entities
    norm_events: list[common.NormalizedEvent] = common.normalize_events(events)
    # Sort chronologically by timestamp, then event_id (deterministic total ordering)
    norm_events.sort(key=lambda e: (e.timestamp, e.event_id))

    event_entities: dict[str, CanonicalEntities] = {
        e.event_id: extract_canonical_entities(
            {
                "actor": e.actor,
                "device": e.device,
                "ip": e.ip,
                "object": e.object,
                "action": e.action,
                "raw": e.raw,
            }
        )
        for e in norm_events
    }

    # 2. Count identifier occurrences for hub suppression
    ip_counts: dict[str, int] = {}
    device_counts: dict[str, int] = {}
    for e in norm_events:
        ent = event_entities[e.event_id]
        if ent.ip:
            ip_counts[ent.ip] = ip_counts.get(ent.ip, 0) + 1
        if ent.device:
            device_counts[ent.device] = device_counts.get(ent.device, 0) + 1

    # 3. Build hash indices for fast candidate pairing (avoids O(n²))
    by_file_object: dict[str, list[tuple[int, common.NormalizedEvent]]] = {}
    by_content_hash: dict[str, list[tuple[int, common.NormalizedEvent]]] = {}
    by_actor_device: dict[tuple[str, str], list[tuple[int, common.NormalizedEvent]]] = {}
    by_device: dict[str, list[tuple[int, common.NormalizedEvent]]] = {}
    by_ip: dict[str, list[tuple[int, common.NormalizedEvent]]] = {}

    for idx, e in enumerate(norm_events):
        ent = event_entities[e.event_id]
        if ent.file_object:
            by_file_object.setdefault(ent.file_object, []).append((idx, e))
        if ent.content_hash:
            by_content_hash.setdefault(ent.content_hash, []).append((idx, e))
        if ent.actor and ent.device:
            by_actor_device.setdefault((ent.actor, ent.device), []).append((idx, e))
        if ent.device:
            by_device.setdefault(ent.device, []).append((idx, e))
        if ent.ip:
            by_ip.setdefault(ent.ip, []).append((idx, e))

    # Effective max window across rules
    effective_max_window = max_window or ARCHIVE_UPLOAD_WINDOW

    candidate_pairs: set[tuple[int, int]] = set()

    def _collect_pairs(bucket: list[tuple[int, common.NormalizedEvent]], max_allowed_window: timedelta) -> None:
        """Sliding-window pair collection within an effective-interval sorted bucket.

        Uses effective time intervals (T2 source-clock correction) so that
        candidate pairing respects source clock offsets and uncertainty.  Two
        events are included as a candidate pair when their effective intervals
        overlap OR when the gap between the nearer edges of the two intervals
        is within ``max_allowed_window``.
        """
        sorted_bucket = sorted(
            bucket,
            key=lambda item: (event_interval(item[1], clocks).lo, item[1].event_id)
        )
        n = len(sorted_bucket)
        for i in range(n):
            idx1, e1 = sorted_bucket[i]
            iv1 = event_interval(e1, clocks)
            for j in range(i + 1, n):
                idx2, e2 = sorted_bucket[j]
                iv2 = event_interval(e2, clocks)
                sep = _interval_separation_seconds(iv1, iv2)
                if iv2.lo > iv1.hi and sep > max_allowed_window.total_seconds():
                    break
                if sep <= max_allowed_window.total_seconds():
                    pair = (min(idx1, idx2), max(idx1, idx2))
                    candidate_pairs.add(pair)

    # Generate candidate pairs from strong and supporting indices
    for bucket in by_file_object.values():
        _collect_pairs(bucket, effective_max_window)
    for bucket in by_content_hash.values():
        _collect_pairs(bucket, effective_max_window)
    for bucket in by_actor_device.values():
        _collect_pairs(bucket, DEFAULT_CORRELATION_WINDOW)

    # For device and IP indices, collect pairs within the window
    for dev, bucket in by_device.items():
        _collect_pairs(bucket, DEFAULT_CORRELATION_WINDOW)
    for ip_val, bucket in by_ip.items():
        _collect_pairs(bucket, DEFAULT_CORRELATION_WINDOW)

    all_candidates: list[CandidateRelationship] = []
    promoted_candidates: list[CandidateRelationship] = []

    # Deterministic evaluation order: sort candidate pairs by (idx1, idx2)
    for idx1, idx2 in sorted(candidate_pairs):
        e1 = norm_events[idx1]
        e2 = norm_events[idx2]

        iv1 = event_interval(e1, clocks)
        iv2 = event_interval(e2, clocks)
        # Order by effective interval midpoint so the chronologically earlier event
        # in true case time is always treated as source.
        if (iv1.midpoint, iv1.lo, e1.event_id) <= (iv2.midpoint, iv2.lo, e2.event_id):
            src, tgt = e1, e2
            iv_src, iv_tgt = iv1, iv2
        else:
            src, tgt = e2, e1
            iv_src, iv_tgt = iv2, iv1

        ent1 = event_entities[src.event_id]
        ent2 = event_entities[tgt.event_id]

        matched_signals: list[str] = []
        reason_codes: list[str] = []
        contradiction_signals: list[str] = []

        # --- T2 Effective-interval time gate evaluation ---------------------
        # Use source-clock-corrected intervals so that source offsets and
        # timestamp uncertainty are accounted for in the gate check.
        sep_seconds = _interval_separation_seconds(iv_src, iv_tgt)
        delta_seconds = abs((iv_tgt.midpoint - iv_src.midpoint).total_seconds())

        staging_actions = {"archive_create", "file_upload", "upload", "file_access", "file_read"}
        is_staging_flow = bool(
            (src.action in staging_actions and tgt.action in staging_actions) or
            (src.action == "message_sent" and tgt.action in staging_actions) or
            (src.action in staging_actions and tgt.action == "message_sent")
        )
        has_file_or_hash = bool(
            (ent1.file_object and ent2.file_object and ent1.file_object == ent2.file_object) or
            (ent1.content_hash and ent2.content_hash and ent1.content_hash == ent2.content_hash)
        )
        gate_window = ARCHIVE_UPLOAD_WINDOW if (is_staging_flow and has_file_or_hash) else DEFAULT_CORRELATION_WINDOW

        if sep_seconds <= gate_window.total_seconds():
            reason_codes.append(REASON_WITHIN_TIME_GATE)
        else:
            # Beyond time gate -> reject immediately
            reason_codes.append(REASON_TEMPORAL_ONLY_REJECTED)

        # Signal 1: Exact file / object key (Strong identifier)
        has_file_match = False
        if ent1.file_object and ent2.file_object and ent1.file_object == ent2.file_object:
            matched_signals.append("exact_file_key")
            reason_codes.append(REASON_EXACT_FILE_KEY)
            has_file_match = True

        # Signal 2: Content hash match (Strong identifier)
        has_hash_match = False
        if ent1.content_hash and ent2.content_hash and ent1.content_hash == ent2.content_hash:
            matched_signals.append("content_hash")
            reason_codes.append(REASON_CONTENT_HASH)
            has_hash_match = True

        # Signal 3: Shared Actor (Supporting identifier)
        has_actor_match = False
        if ent1.actor and ent2.actor:
            if ent1.actor == ent2.actor:
                matched_signals.append("same_actor")
                reason_codes.append(REASON_SAME_ACTOR)
                has_actor_match = True
            else:
                contradiction_signals.append(f"Actor mismatch: '{ent1.actor}' vs '{ent2.actor}'")

        # Signal 4: Shared Device (Supporting identifier)
        has_device_match = False
        device_weight = 0.5
        if ent1.device and ent2.device:
            if ent1.device == ent2.device:
                matched_signals.append("same_device")
                reason_codes.append(REASON_SAME_DEVICE)
                has_device_match = True
                dev_count = device_counts.get(ent1.device, 1)
                if dev_count > DEVICE_HUB_THRESHOLD:
                    dev_factor = _hub_factor(dev_count, DEVICE_HUB_THRESHOLD)
                    device_weight *= dev_factor
                    if REASON_HUB_SUPPRESSED not in reason_codes:
                        reason_codes.append(REASON_HUB_SUPPRESSED)
            else:
                # Different devices is normal in cross-device workflows, not a contradiction
                pass

        # Signal 5: Shared IP (Weak signal)
        has_ip_match = False
        ip_weight = 0.2
        if ent1.ip and ent2.ip and ent1.ip == ent2.ip:
            matched_signals.append("shared_ip")
            reason_codes.append(REASON_SHARED_IP)
            has_ip_match = True
            count = ip_counts.get(ent1.ip, 1)
            if count > IP_HUB_THRESHOLD:
                factor = _hub_factor(count, IP_HUB_THRESHOLD)
                ip_weight *= factor
                if REASON_HUB_SUPPRESSED not in reason_codes:
                    reason_codes.append(REASON_HUB_SUPPRESSED)

        # Signal 6: Action sequence compatibility
        seq_status, is_seq_boost = _check_sequence_compatibility(
            src.action, tgt.action, iv_src.midpoint, iv_tgt.midpoint
        )
        if is_seq_boost:
            matched_signals.append("sequence_compatible")
            reason_codes.append(REASON_SEQUENCE_COMPATIBLE)
        elif seq_status == "INCOMPATIBLE":
            contradiction_signals.append(
                f"Incompatible operational sequence: '{src.action}' after '{tgt.action}'"
            )

        # Compute deterministic ranking score
        score = 0.0
        if has_file_match:
            score += 1.0
        if has_hash_match:
            score += 1.0
        if has_actor_match:
            score += 0.5
        if has_device_match:
            score += device_weight
        if has_ip_match:
            score += ip_weight
        if is_seq_boost:
            score += 0.5

        if contradiction_signals:
            score -= 1.5
            reason_codes.append(REASON_CONTRADICTORY_IDENTIFIER)

        score = round(max(0.0, score), 3)

        # -------------------------------------------------------------------
        # Promotion decision logic
        # -------------------------------------------------------------------
        is_promoted = False
        time_gated = REASON_WITHIN_TIME_GATE in reason_codes
        no_contradiction = len(contradiction_signals) == 0

        # Identifier requirements for promotion:
        # 1. At least one strong identifier (exact file key or content hash)
        # OR
        # 2. Both supporting identifiers (same actor + same device) without hub degradation
        has_strong_id = has_file_match or has_hash_match
        has_supported_binding = has_actor_match and has_device_match and (device_weight >= 0.25)

        if not has_strong_id and not has_supported_binding:
            reason_codes.append(REASON_INSUFFICIENT_IDENTIFIER)

        if time_gated and no_contradiction and seq_status == "COMPATIBLE":
            if has_strong_id or (has_supported_binding and is_seq_boost):
                # H″ rule: identifier signal + sequence compatibility.
                # A strong identifier or matching content hash must NOT independently
                # promote a relationship when sequence compatibility is NEUTRAL.
                # Promotion requires compatible action sequence alongside a strong identifier
                # or supported actor+device binding.
                is_promoted = True

        candidate_type = "SAME_OBJECT_FLOW" if has_file_match or has_hash_match else "EVENT_CORRELATION"
        candidate_id = _compute_candidate_id(src.event_id, tgt.event_id, candidate_type, f"{idx1}_{idx2}")

        canonical_entities_dict = {
            "source": ent1.to_dict(),
            "target": ent2.to_dict(),
            "shared_object": ent1.file_object if has_file_match else None,
            "shared_content_hash": ent1.content_hash if has_hash_match else None,
            "shared_actor": ent1.actor if has_actor_match else None,
            "shared_device": ent1.device if has_device_match else None,
            "shared_ip": ent1.ip if has_ip_match else None,
        }

        cand = CandidateRelationship(
            candidate_id=candidate_id,
            source_event_id=src.event_id,
            target_event_id=tgt.event_id,
            candidate_type=candidate_type,
            matched_signals=matched_signals,
            canonical_entities=canonical_entities_dict,
            temporal_delta=delta_seconds,
            sequence_compatibility=seq_status,
            contradiction_signals=contradiction_signals,
            score=score,
            promotion_decision=is_promoted,
            reason_codes=sorted(set(reason_codes)),
        )

        all_candidates.append(cand)
        if is_promoted:
            promoted_candidates.append(cand)

    # Sort deterministically: highest score first, then source_id, target_id
    all_candidates.sort(key=lambda c: (-c.score, c.source_event_id, c.target_event_id))
    promoted_candidates.sort(key=lambda c: (-c.score, c.source_event_id, c.target_event_id))

    return all_candidates, promoted_candidates


def correlate_events(
    events: Sequence[Mapping[str, Any] | common.NormalizedEvent],
) -> tuple[list[CandidateRelationship], list[CandidateRelationship]]:
    """Public T5 engine entry point returning (candidates, promoted_links)."""
    return generate_candidates(events)


def correlate(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Role 2 compatibility interface.

    Preserves the legacy `correlate(events) -> list[Finding]` contract
    so existing tests and intelligence.analyze() continue working seamlessly.
    """
    if len(events) < 2:
        return []

    all_cands, _ = generate_candidates(events)
    eligible = [
        cand for cand in all_cands
        if REASON_WITHIN_TIME_GATE in cand.reason_codes
        and ("exact_file_key" in cand.matched_signals or "content_hash" in cand.matched_signals)
        and not cand.contradiction_signals
    ]
    if not eligible:
        return []

    events_by_id = {e["event_id"]: e for e in events if "event_id" in e}
    known_event_ids = common.extract_event_ids(events)

    findings: list[dict[str, Any]] = []
    case_id = events[0].get("case_id", "CASE-UNKNOWN")

    for cand in eligible:
        e1 = events_by_id.get(cand.source_event_id)
        e2 = events_by_id.get(cand.target_event_id)
        if not e1 or not e2:
            continue

        # Determine display representation of the shared object preserving original casing
        display_obj = None
        for ev_item in (e1, e2):
            raw_obj = ev_item.get("object")
            if isinstance(raw_obj, str) and raw_obj.strip():
                if "://" not in raw_obj:
                    display_obj = raw_obj.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
                    break
        if display_obj is None:
            for ev_item in (e1, e2):
                raw_obj = ev_item.get("object")
                if isinstance(raw_obj, str) and "://" in raw_obj:
                    from urllib.parse import urlparse, unquote
                    parsed = urlparse(raw_obj)
                    path = parsed.path.rstrip("/")
                    if path and path != "/":
                        display_obj = unquote(path.rsplit("/", 1)[-1])
                        break
        if display_obj is None:
            display_obj = (
                cand.canonical_entities.get("shared_object")
                or cand.canonical_entities.get("shared_content_hash")
                or "object"
            )

        is_archive_upload = (
            (e1.get("action") == "archive_create" and e2.get("action") == "file_upload") or
            (e1.get("action") == "file_upload" and e2.get("action") == "archive_create")
        )

        if is_archive_upload:
            rule_id = "same_object_archive_upload_within_30m"
            window_spec = 30
        else:
            rule_id = "same_object_within_10m"
            window_spec = 10

        action_labels = {
            "archive_create": "archive creation",
            "file_upload": "file upload",
            "login": "login",
            "session_start": "session start",
        }
        raw_action1 = str(e1.get("action") or "activity")
        raw_action2 = str(e2.get("action") or "activity")
        action1 = action_labels.get(raw_action1, raw_action1.replace("_", " "))
        action2 = action_labels.get(raw_action2, raw_action2.replace("_", " "))
        source1 = str(e1.get("source") or "source")
        source2 = str(e2.get("source") or "source")
        delta_minutes = cand.temporal_delta / 60.0
        claim = (
            f"The file '{display_obj}' appears in {action1} ({source1}) "
            f"and {action2} ({source2}) {delta_minutes:.1f} minutes apart."
        )
        reasoning = (
            f"Both events reference the same object, '{display_obj}'. The first "
            f"was recorded by {source1} ({action1}); the second by {source2} "
            f"({action2}). Their timestamps are {delta_minutes:.1f} minutes "
            f"apart, within the {window_spec}-minute correlation window. "
            f"This establishes a temporal/object correlation, not by itself "
            f"that the activity was unauthorized."
        )

        finding = common.make_finding(
            case_id=case_id,
            finding_type="correlation",
            rule_id=rule_id,
            claim=claim,
            confidence=0.8,
            evidence_event_ids=[e1["event_id"], e2["event_id"]],
            reasoning=reasoning,
            known_event_ids=known_event_ids,
            needs_human_review=True,
        )
        findings.append(finding)

    return findings
