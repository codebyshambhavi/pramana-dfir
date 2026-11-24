"""Role 3 / T8: Narrative Reconstruction Engine with Interval Logic.

Reconstructs forensic hypotheses into chronological stages:
- Computed view over immutable runs, claims, and events.
- Stage status: SUPPORTED vs GAP.
- Rigorous interval arithmetic using TimeInterval: overlapping intervals
  must not be asserted as definite precedence.
- Identifies background activity and unassigned H0 residuals.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Mapping, Sequence

from intelligence.timeline import (
    NO_CLOCK_ERROR,
    SourceClock,
    TimeInterval,
    effective_interval,
    load_source_clocks,
)
from .engine import (
    HypothesisTemplate,
    RankedHypothesis,
    _claim_to_dict,
    _matches_item,
    _relationship_has_contradiction,
    adapt_relationships_for_hypotheses,
    load_templates,
    normalize_event_contract,
)


@dataclass
class StageReconstruction:
    stage_name: str
    status: str  # "SUPPORTED" or "GAP"
    time_window: dict[str, str] | None = None  # {"lo": iso, "hi": iso}
    relationship_to_previous: str = "FIRST_STAGE"  # PRECEDES, CONCURRENT_OR_OVERLAPPING, OUT_OF_ORDER, UNPROVEN, GAP_DETECTED
    claims: list[dict[str, Any]] = field(default_factory=list)
    raw_events: list[dict[str, Any]] = field(default_factory=list)
    relationship_ids: list[str] = field(default_factory=list)
    contradictions: list[dict[str, Any]] = field(default_factory=list)
    chronology_uncertainty: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NarrativeReconstruction:
    hypothesis_id: str
    hypothesis_name: str
    status: str
    stages: list[StageReconstruction]
    background_activity_count: int
    background_activity_event_ids: list[str]
    residual_h0_count: int
    residual_h0_event_ids: list[str]
    narrative_summary: str
    case_id: str | None = None
    analysis_run_id: str | None = None
    timeline_events: list[dict[str, Any]] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    relationship_ids: list[str] = field(default_factory=list)
    contradictions: list[dict[str, Any]] = field(default_factory=list)
    chronology_uncertainties: list[dict[str, Any]] = field(default_factory=list)
    missing_timestamp_event_ids: list[str] = field(default_factory=list)
    missing_timestamp_events: list[dict[str, Any]] = field(default_factory=list)
    conflicting_timestamp_events: list[dict[str, Any]] = field(default_factory=list)
    duplicate_event_ids: list[str] = field(default_factory=list)

    @property
    def events(self) -> list[dict[str, Any]]:
        return self.timeline_events

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["stages"] = [s.to_dict() for s in self.stages]
        d["events"] = list(self.timeline_events)
        return d


def _parse_utc_datetime(val: Any) -> datetime | None:
    if isinstance(val, datetime):
        return val.astimezone(timezone.utc).replace(tzinfo=None) if val.tzinfo else val
    if isinstance(val, str):
        s = val.strip()
        if not s:
            return None
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt
        except ValueError:
            return None
    return None


def _format_utc_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt.microsecond else dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def extract_source_locator_details(event: Mapping[str, Any]) -> dict[str, Any]:
    """Extract structured source locator metadata while preserving the original locator.

    Handles:
    - Email Message ID (Gmail/Outlook/RFC Message-ID)
    - PST folder path and item identifier
    - PCAP packet/frame number
    - Zeek UID and record index
    - Log line/row/offset
    """
    raw = event.get("raw") if isinstance(event.get("raw"), Mapping) else {}
    raw_locator = event.get("source_locator")
    artifact_ref = event.get("artifact_ref")
    loc_str = str(raw_locator if raw_locator is not None else (artifact_ref or ""))

    details: dict[str, Any] = {}
    if artifact_ref is not None:
        details["artifact_ref"] = artifact_ref
    if isinstance(raw_locator, Mapping):
        details.update(dict(raw_locator))

    # 1. Email Message ID
    msg_id = (
        details.get("message_id")
        or event.get("message_id")
        or raw.get("internetMessageId")
        or raw.get("message_id")
        or raw.get("Message-ID")
        or raw.get("Message-Id")
        or (raw.get("raw_headers", {}).get("message-id") if isinstance(raw.get("raw_headers"), Mapping) else None)
        or (raw.get("id") if event.get("source") in ("gmail", "outlook") else None)
    )
    if not msg_id:
        m = re.search(r"(?:#|:|&|^)(?:(?:gmail|outlook)-message|message_id)=([^#&]+)", loc_str)
        if m:
            msg_id = m.group(1)
    if msg_id is not None:
        details["message_id"] = str(msg_id)

    # 2. PST folder & item identifier
    pst_folder = details.get("folder_path") or raw.get("folder_path")
    pst_item = (
        details.get("item_identifier")
        or details.get("item_id")
        or raw.get("item_identifier")
        or raw.get("item_id")
    )
    if not pst_folder and (event.get("source") == "pst" or loc_str.lower().startswith("pst:")):
        m_folder = re.search(r"^pst:([^#]+)", loc_str, flags=re.IGNORECASE)
        if m_folder:
            pst_folder = m_folder.group(1)
    if pst_item is None:
        m_item = re.search(r"(?:#|&)(?:item_id|item_identifier)=([^#&]+)", loc_str)
        if m_item:
            pst_item = m_item.group(1)
    if (not pst_folder or pst_item is None) and (event.get("source") == "pst" or ".pst#" in loc_str.lower()):
        parts = loc_str.split("#")
        if len(parts) >= 3:
            pst_folder = pst_folder or parts[1]
            pst_item = pst_item if pst_item is not None else parts[2]
    if pst_folder is not None:
        details["pst_folder_path"] = str(pst_folder)
    if pst_item is not None:
        details["pst_item_id"] = str(pst_item)

    # 3. PCAP packet / frame number
    pkt_num = (
        details.get("packet_number")
        if "packet_number" in details
        else (
            raw.get("packet_number")
            if "packet_number" in raw
            else (details.get("frame_number") if "frame_number" in details else raw.get("frame_number"))
        )
    )
    if pkt_num is None:
        m = re.search(r"(?:#|&|^)(?:packet|frame)=(\d+)", loc_str)
        if m:
            pkt_num = int(m.group(1))
    if pkt_num is not None:
        details["packet_number"] = pkt_num

    # 4. Zeek UID
    zeek_uid = details.get("zeek_uid") or details.get("uid") or raw.get("uid") or raw.get("zeek_uid")
    if not zeek_uid:
        m_uid = re.search(r"(?:#|&|:|^)(?:zeek_uid|uid)=([^#&]+)", loc_str)
        if m_uid:
            zeek_uid = m_uid.group(1)
    if zeek_uid is not None:
        details["zeek_uid"] = str(zeek_uid)

    # 5. Original log line or offset
    line_num = (
        details.get("line_number")
        or details.get("line")
        or details.get("row")
        or raw.get("line_number")
        or raw.get("line")
        or raw.get("row")
    )
    if line_num is None:
        m_line = re.search(r"(?:#|&|^)(?:line|row)=(\d+)", loc_str)
        if m_line:
            line_num = int(m_line.group(1))
    if line_num is not None:
        try:
            details["line_number"] = int(line_num)
        except (TypeError, ValueError):
            details["line_number"] = line_num

    byte_off = (
        details.get("byte_offset")
        or details.get("offset")
        or raw.get("byte_offset")
        or raw.get("offset")
    )
    if byte_off is None:
        m_off = re.search(r"(?:#|&|^)(?:byte_offset|offset)=(\d+)", loc_str)
        if m_off:
            byte_off = int(m_off.group(1))
    if byte_off is not None:
        try:
            details["byte_offset"] = int(byte_off)
        except (TypeError, ValueError):
            details["byte_offset"] = byte_off

    line_offset = (
        details.get("log_line_offset")
        or details.get("row")
        or details.get("line")
        or details.get("offset")
        or raw.get("row")
        or raw.get("line")
        or raw.get("offset")
        or line_num
        or byte_off
    )
    if line_offset is None:
        m = re.search(r"#(row|line|offset|conn|dns)=([^#&]+)", loc_str)
        if m:
            line_offset = f"{m.group(1)}={m.group(2)}"
    if line_offset is not None:
        details["log_line_offset"] = line_offset

    return details


def normalize_event_for_reconstruction(
    event: Mapping[str, Any],
    *,
    clocks: Mapping[str, SourceClock] | None = None,
    case_id: str | None = None,
    analysis_run_id: str | None = None,
) -> dict[str, Any]:
    """Normalize an input event into the T8 reconstructed timeline event schema.

    Guarantees preservation of:
    - event_id, case_id, evidence_id
    - event_type (and action)
    - event_time_utc (and timestamp)
    - raw_timestamp
    - source_locator (and artifact_ref + source_locator_details)
    - extraction_quality (preserving timezone certainty, clock quality, parser confidence, warnings)
    """
    ev = normalize_event_contract(event)
    if not ev.get("event_id") or not isinstance(ev.get("event_id"), str):
        raise ValueError("Event is missing a valid string 'event_id'")
    if case_id and not ev.get("case_id"):
        ev["case_id"] = case_id

    src = str(ev.get("source") or "unknown")
    clock = (clocks or {}).get(src, NO_CLOCK_ERROR)

    raw_ts_input = ev.get("timestamp") if ev.get("timestamp") is not None else ev.get("event_time_utc")
    dt = _parse_utc_datetime(raw_ts_input)
    utc_iso = _format_utc_iso(dt)

    # Preserve original timestamp field for backward compatibility, and set normalized event_time_utc
    ev["event_time_utc"] = utc_iso
    if ev.get("timestamp") is None and utc_iso is not None:
        ev["timestamp"] = utc_iso

    # Source locator & details
    loc_details = extract_source_locator_details(ev)
    ev["source_locator_details"] = loc_details
    if ev.get("source_locator") is None:
        if ev.get("artifact_ref"):
            ev["source_locator"] = ev["artifact_ref"]
        elif loc_details.get("message_id"):
            ev["source_locator"] = f"message_id={loc_details['message_id']}"
        elif loc_details.get("zeek_uid"):
            ev["source_locator"] = f"zeek_uid={loc_details['zeek_uid']}"
        elif loc_details.get("pst_folder_path") is not None:
            ev["source_locator"] = f"pst:{loc_details.get('pst_folder_path')}#{loc_details.get('pst_item_id', '')}"
        elif loc_details.get("packet_number") is not None:
            ev["source_locator"] = f"packet={loc_details['packet_number']}"
        elif loc_details.get("log_line_offset") is not None:
            ev["source_locator"] = str(loc_details["log_line_offset"])

    # Extraction quality: preserve timezone uncertainty and timestamp quality
    tz_assumption = ev.get("tz_assumption")
    orig_eq = event.get("extraction_quality")
    eq = dict(orig_eq) if isinstance(orig_eq, Mapping) else {}
    if not tz_assumption:
        tz_assumption = eq.get("tz_assumption")
        if not tz_assumption and isinstance(raw_ts_input, str) and raw_ts_input.strip():
            s = raw_ts_input.strip()
            if s.endswith("Z") or re.search(r"[+-]\d\d:\d\d$", s):
                tz_assumption = "explicit_offset"
            elif dt is not None:
                tz_assumption = "assumed_utc"
    tz_assumption = tz_assumption or "unknown"
    ev.setdefault("tz_assumption", tz_assumption)

    if dt is None:
        ts_quality = "missing" if raw_ts_input in (None, "") else "unparseable"
    elif tz_assumption in ("explicit_offset", "explicit_utc", "epoch_utc"):
        ts_quality = eq.get("timestamp_quality") or "explicit_utc"
    else:
        ts_quality = eq.get("timestamp_quality") or "assumed_timezone"

    tz_certainty = (
        "explicit"
        if tz_assumption in ("explicit_offset", "explicit_utc", "epoch_utc")
        else ("assumed_utc" if tz_assumption == "assumed_utc" else "uncertain")
    )

    eq.setdefault("tz_assumption", tz_assumption)
    eq.setdefault("timezone_certainty", tz_certainty)
    eq["timestamp_quality"] = ts_quality
    eq.setdefault("clock_offset_seconds", clock.offset.total_seconds())
    eq.setdefault("clock_uncertainty_seconds", clock.uncertainty.total_seconds())
    eq.setdefault("parser_version", ev.get("parser_version"))
    if isinstance(orig_eq, str) and orig_eq.strip():
        ev["extraction_quality"] = orig_eq.strip()
        ev["extraction_quality_details"] = eq
    else:
        ev["extraction_quality"] = eq

    # Detect discrepancy between explicit event_time_utc and explicit raw_timestamp (when raw_timestamp carries an explicit offset/Z)
    raw_ts_val = event.get("raw_timestamp")
    discrepancy_seconds: float | None = None
    has_ts_conflict = False
    if dt is not None and isinstance(raw_ts_val, str) and raw_ts_val.strip():
        s_raw = raw_ts_val.strip()
        if s_raw.endswith("Z") or re.search(r"[+-]\d\d:\d\d$", s_raw):
            dt_raw = _parse_utc_datetime(s_raw)
            if dt_raw is not None:
                diff_s = abs((dt - dt_raw).total_seconds())
                if diff_s > 1.0:
                    has_ts_conflict = True
                    discrepancy_seconds = diff_s

    # Effective interval & chronology uncertainty
    iv = effective_interval(dt, clock) if dt is not None else None
    has_uncertainty = (
        iv is None
        or has_ts_conflict
        or clock.uncertainty.total_seconds() > 0
        or tz_certainty != "explicit"
    )
    ordering_status = (
        "MISSING_TIMESTAMP"
        if iv is None
        else (
            "CONFLICTING_TIMESTAMPS"
            if has_ts_conflict
            else ("UNCERTAIN_INTERVAL" if clock.uncertainty.total_seconds() > 0 else "DEFINITE")
        )
    )
    ev["chronology_uncertainty"] = {
        "status": ordering_status,
        "effective_interval": (
            {"lo": iv.lo.isoformat() + "Z", "hi": iv.hi.isoformat() + "Z"} if iv is not None else None
        ),
        "clock_offset_seconds": clock.offset.total_seconds(),
        "clock_uncertainty_seconds": clock.uncertainty.total_seconds(),
        "tz_assumption": tz_assumption,
        "timezone_certainty": tz_certainty,
        "timestamp_quality": ts_quality,
        "has_uncertainty": has_uncertainty,
        "has_timestamp_conflict": has_ts_conflict,
        "discrepancy_seconds": discrepancy_seconds,
        "ordering_certainty": ordering_status,
    }

    if analysis_run_id is not None:
        ev["analysis_run_id"] = analysis_run_id

    ev.setdefault("relationship_ids", [])
    ev.setdefault("relationships", [])
    ev.setdefault("hypothesis_ids", [])
    ev.setdefault("claim_ids", [])
    ev.setdefault("contradictions", [])
    return ev


def reconstruct_narrative(
    hypothesis: RankedHypothesis | HypothesisTemplate | str,
    claims: Sequence[Any],
    events: Sequence[Mapping[str, Any]],
    source_clocks: Mapping[str, SourceClock] | None = None,
    h0_event_ids: Sequence[str] | None = None,
    templates: Sequence[HypothesisTemplate] | None = None,
    *,
    relationships: Sequence[Mapping[str, Any]] | None = None,
    case_id: str | None = None,
    analysis_run_id: str | None = None,
) -> NarrativeReconstruction:
    """Reconstruct a hypothesis into chronological stages with interval analysis.

    Args:
        hypothesis: RankedHypothesis object, HypothesisTemplate, or hypothesis ID string ("H1", "H2", "H3").
        claims: Evaluated claims from the analysis run.
        events: Ingested case events (Event v1.1 or Section 5.6 Normalized Event format).
        source_clocks: Optional SourceClock uncertainties.
        h0_event_ids: Optional precomputed H0 residual event IDs.
        templates: Optional explicit hypothesis templates (e.g. preserved from run snapshot).
                   When provided, templates are NEVER loaded from disk.
        relationships: Optional sequence of correlation relationship objects.
        case_id: Optional case identifier for strict case-isolation enforcement.
        analysis_run_id: Optional analysis run identifier to retain on reconstructed outputs.

    Returns:
        NarrativeReconstruction computed view.
    """
    clocks = dict(source_clocks) if source_clocks is not None else load_source_clocks()

    # Resolve template first
    if isinstance(hypothesis, HypothesisTemplate):
        tmpl = hypothesis
        hyp_id = tmpl.id
    else:
        hyp_id = hypothesis.id if hasattr(hypothesis, "id") else str(hypothesis)
        if templates is not None:
            all_templates = {t.id: t for t in templates}
        else:
            all_templates = {t.id: t for t in load_templates()}
        tmpl = all_templates.get(hyp_id)
        if not tmpl:
            raise ValueError(f"Unknown hypothesis '{hyp_id}'")

    hyp_name = tmpl.name
    hyp_status = getattr(hypothesis, "status", "VIABLE")
    resolved_run_id = analysis_run_id or getattr(hypothesis, "analysis_run_id", None)
    resolved_case_id = case_id or getattr(hypothesis, "case_id", None)

    # Normalize events, enforce case isolation, and handle duplicate/conflicting events
    events_by_id: dict[str, dict[str, Any]] = {}
    ordered_unique_events: list[dict[str, Any]] = []
    duplicate_event_ids: list[str] = []
    missing_timestamp_event_ids: list[str] = []
    all_contradictions: list[dict[str, Any]] = []

    for raw_e in events:
        norm_e = normalize_event_for_reconstruction(
            raw_e,
            clocks=clocks,
            case_id=resolved_case_id,
            analysis_run_id=resolved_run_id,
        )
        ev_case = norm_e.get("case_id")
        if isinstance(ev_case, str) and ev_case.strip():
            if resolved_case_id is None:
                resolved_case_id = ev_case.strip()
            elif ev_case.strip() != resolved_case_id:
                raise ValueError(
                    f"Case isolation violation: event '{norm_e['event_id']}' belongs to case '{ev_case}', "
                    f"expected '{resolved_case_id}'"
                )

        eid = norm_e["event_id"]
        if eid in events_by_id:
            if eid not in duplicate_event_ids:
                duplicate_event_ids.append(eid)
            existing = events_by_id[eid]
            # Check if the duplicate has a conflicting timestamp or conflicting core attributes
            if existing.get("event_time_utc") != norm_e.get("event_time_utc") or (
                existing.get("raw_timestamp") != norm_e.get("raw_timestamp")
                and norm_e.get("raw_timestamp") is not None
                and existing.get("raw_timestamp") is not None
            ):
                conflict_record = {
                    "type": "CONFLICTING_EVENT_TIMESTAMP",
                    "event_id": eid,
                    "primary_timestamp": existing.get("event_time_utc") or existing.get("raw_timestamp"),
                    "conflicting_timestamp": norm_e.get("event_time_utc") or norm_e.get("raw_timestamp"),
                    "evidence_id": existing.get("evidence_id"),
                    "source_locator": existing.get("source_locator"),
                    "description": (
                        f"Duplicate event '{eid}' observed with conflicting timestamps: "
                        f"{existing.get('event_time_utc') or existing.get('raw_timestamp')} vs "
                        f"{norm_e.get('event_time_utc') or norm_e.get('raw_timestamp')}."
                    ),
                }
                existing["contradictions"].append(conflict_record)
                existing["chronology_uncertainty"]["has_uncertainty"] = True
                existing["chronology_uncertainty"]["has_timestamp_conflict"] = True
                existing["chronology_uncertainty"]["ordering_certainty"] = "CONFLICTING_TIMESTAMPS"
                all_contradictions.append(conflict_record)
            continue

        if norm_e.get("event_time_utc") is None:
            missing_timestamp_event_ids.append(eid)

        events_by_id[eid] = norm_e
        ordered_unique_events.append(norm_e)

    # Also detect different event_ids referencing the exact same non-empty source_locator + evidence_id
    # with conflicting timestamps
    by_locator_key: dict[tuple[str, str], dict[str, Any]] = {}
    for ev in ordered_unique_events:
        evid = str(ev.get("evidence_id") or "")
        loc = str(ev.get("source_locator") or "")
        if evid and loc:
            lkey = (evid, loc)
            prev_ev = by_locator_key.get(lkey)
            if prev_ev is not None and prev_ev["event_id"] != ev["event_id"]:
                if (
                    prev_ev.get("event_time_utc")
                    and ev.get("event_time_utc")
                    and prev_ev.get("event_time_utc") != ev.get("event_time_utc")
                ):
                    conflict_record = {
                        "type": "CONFLICTING_LOCATOR_TIMESTAMP",
                        "event_ids": [prev_ev["event_id"], ev["event_id"]],
                        "evidence_id": evid,
                        "source_locator": loc,
                        "timestamps": [prev_ev["event_time_utc"], ev["event_time_utc"]],
                        "description": (
                            f"Events '{prev_ev['event_id']}' and '{ev['event_id']}' share source locator '{loc}' "
                            f"with conflicting timestamps ({prev_ev['event_time_utc']} vs {ev['event_time_utc']})."
                        ),
                    }
                    prev_ev["contradictions"].append(conflict_record)
                    ev["contradictions"].append(conflict_record)
                    prev_ev["chronology_uncertainty"]["has_uncertainty"] = True
                    prev_ev["chronology_uncertainty"]["has_timestamp_conflict"] = True
                    ev["chronology_uncertainty"]["has_uncertainty"] = True
                    ev["chronology_uncertainty"]["has_timestamp_conflict"] = True
                    all_contradictions.append(conflict_record)
            else:
                by_locator_key[lkey] = ev

    # Normalize claims and enforce case isolation
    dict_claims: list[dict[str, Any]] = []
    for c in claims:
        cd = _claim_to_dict(c)
        c_case = cd.get("case_id")
        if isinstance(c_case, str) and c_case.strip():
            if resolved_case_id is None:
                resolved_case_id = c_case.strip()
            elif c_case.strip() != resolved_case_id:
                raise ValueError(
                    f"Case isolation violation: claim '{cd.get('claim_id')}' belongs to case '{c_case}', "
                    f"expected '{resolved_case_id}'"
                )
        dict_claims.append(cd)

    # Validate and attach relationships if provided
    norm_relationships: list[dict[str, Any]] = []
    rel_derived_claims: list[dict[str, Any]] = []
    if relationships is not None:
        if not isinstance(relationships, Sequence) or isinstance(relationships, (str, bytes)):
            raise ValueError("relationships must be a sequence of relationship mappings")
        norm_relationships, rel_derived_claims = adapt_relationships_for_hypotheses(
            relationships,
            ordered_unique_events,
            case_id=resolved_case_id,
        )
        if resolved_case_id is None and norm_relationships:
            resolved_case_id = norm_relationships[0]["case_id"]

    # Attach relationship references and relationship-level contradictions to reconstructed events
    for r in norm_relationships:
        rid = r["relationship_id"]
        rtype = r["relationship_type"]
        src_id = r["source_event_id"]
        dst_id = r["target_event_id"]
        has_contra = _relationship_has_contradiction(r)

        for ev_id, peer_id in ((src_id, dst_id), (dst_id, src_id)):
            ev = events_by_id.get(ev_id)
            if ev is not None:
                if rid not in ev["relationship_ids"]:
                    ev["relationship_ids"].append(rid)
                ev["relationships"].append({
                    "relationship_id": rid,
                    "relationship_type": rtype,
                    "peer_event_id": peer_id,
                    "score": r.get("score"),
                    "review_status": r.get("review_status"),
                    "explanation": r.get("explanation"),
                    "has_counter_signals": has_contra,
                })
                if has_contra:
                    contra_entry = {
                        "type": "RELATIONSHIP_COUNTER_SIGNAL",
                        "relationship_id": rid,
                        "relationship_type": rtype,
                        "peer_event_id": peer_id,
                        "counter_signals": r.get("counter_signals", []),
                        "description": r.get("explanation", f"Contradiction signal on relationship '{rid}'"),
                    }
                    ev["contradictions"].append(contra_entry)
                    if not any(
                        c.get("type") == "RELATIONSHIP_COUNTER_SIGNAL" and c.get("relationship_id") == rid
                        for c in all_contradictions
                    ):
                        all_contradictions.append(contra_entry)

    # When claims were not pre-populated (or non-DB claims), allow relationship-derived claims to link stages
    has_persisted_run_claims = any(isinstance(c.get("run_id"), str) and c.get("run_id") for c in dict_claims)
    if rel_derived_claims and not has_persisted_run_claims:
        existing_claim_ids = {c.get("claim_id") for c in dict_claims if c.get("claim_id")}
        for rc in rel_derived_claims:
            if rc.get("claim_id") not in existing_claim_ids:
                dict_claims.append(rc)

    # Record claim-level contradictions (e.g. LOCATION_CONFLICT, SESSION_ORIGIN_MISMATCH, REFUTED/CONTESTED claims)
    for c in dict_claims:
        ctype = c.get("type")
        cstatus = c.get("status")
        cid = c.get("claim_id")
        is_contra_claim = (
            ctype in ("LOCATION_CONFLICT", "SESSION_ORIGIN_MISMATCH")
            or cstatus in ("REFUTED", "CONTESTED")
            or bool(c.get("is_contradiction_signal"))
        )
        edges = c.get("edges") or []
        for edge in edges:
            ref_kind = getattr(edge, "ref_kind", None) or (edge.get("ref_kind") if isinstance(edge, dict) else None)
            ref_id = getattr(edge, "ref_id", None) or (edge.get("ref_id") if isinstance(edge, dict) else None)
            role = getattr(edge, "role", None) or (edge.get("role") if isinstance(edge, dict) else None)
            if ref_kind == "event" and ref_id in events_by_id:
                ev = events_by_id[ref_id]
                if cid and cid not in ev["claim_ids"]:
                    ev["claim_ids"].append(cid)
                    if is_contra_claim or role == "CONTRADICTS":
                        c_entry = {
                            "type": ctype or f"CLAIM_{ctype}",
                            "claim_type": f"CLAIM_{ctype}",
                            "claim_id": cid,
                            "claim_status": cstatus,
                            "event_id": ref_id,
                            "description": f"Contradiction/conflict claim {ctype} ({cstatus}) references event '{ref_id}'.",
                        }
                        if not any(x.get("claim_id") == cid and x.get("type") == c_entry["type"] for x in ev["contradictions"]):
                            ev["contradictions"].append(c_entry)
                        if not any(x.get("claim_id") == cid and x.get("event_id") == ref_id for x in all_contradictions):
                            all_contradictions.append(c_entry)

    # Map template items to stages
    stage_claims: dict[str, list[dict[str, Any]]] = {st: [] for st in tmpl.stages}
    stage_events: dict[str, list[dict[str, Any]]] = {st: [] for st in tmpl.stages}
    stage_intervals: dict[str, TimeInterval | None] = {st: None for st in tmpl.stages}

    # Associate claims with stages based on template requires & expects
    relevant_items = tmpl.requires + tmpl.expects
    hyp_assigned_event_ids: set[str] = set()

    for item in relevant_items:
        matching = [
            c for c in dict_claims
            if _matches_item(item, c, events_by_id)
            and c.get("status") in ("ASSERTED", "CORROBORATED", "CONTESTED")
        ]

        for c in matching:
            if not c.get("relationship_backed") or not has_persisted_run_claims:
                if c not in stage_claims[item.stage]:
                    stage_claims[item.stage].append(c)

            edges = c.get("edges") or []
            for edge in edges:
                ref_kind = getattr(edge, "ref_kind", None) or (edge.get("ref_kind") if isinstance(edge, dict) else None)
                ref_id = getattr(edge, "ref_id", None) or (edge.get("ref_id") if isinstance(edge, dict) else None)
                if ref_kind == "event" and ref_id in events_by_id:
                    ev = events_by_id[ref_id]
                    if hyp_id not in ev["hypothesis_ids"]:
                        ev["hypothesis_ids"].append(hyp_id)
                    ev.setdefault("stage", item.stage)
                    if ev not in stage_events[item.stage]:
                        stage_events[item.stage].append(ev)
                    hyp_assigned_event_ids.add(ref_id)

    # Compute TimeInterval for each stage and detect intra-stage overlapping/ambiguous intervals
    for st in tmpl.stages:
        evs = stage_events[st]
        intervals: list[tuple[dict[str, Any], TimeInterval]] = []
        for e in evs:
            dt = _parse_utc_datetime(e.get("event_time_utc") or e.get("timestamp"))
            if dt is not None:
                src = e.get("source") or "unknown"
                clock = clocks.get(src, NO_CLOCK_ERROR)
                iv = effective_interval(dt, clock)
                intervals.append((e, iv))

        # Check pairwise overlaps within the stage
        for i in range(len(intervals)):
            for j in range(i + 1, len(intervals)):
                ev_i, iv_i = intervals[i]
                ev_j, iv_j = intervals[j]
                if iv_i.overlaps(iv_j):
                    for target_ev in (ev_i, ev_j):
                        target_ev["chronology_uncertainty"]["has_uncertainty"] = True
                        if target_ev["chronology_uncertainty"]["ordering_certainty"] == "DEFINITE":
                            target_ev["chronology_uncertainty"]["ordering_certainty"] = "CONCURRENT_OR_OVERLAPPING"

        if intervals:
            lo = min(i.lo for _, i in intervals)
            hi = max(i.hi for _, i in intervals)
            stage_intervals[st] = TimeInterval(lo, hi)
        else:
            stage_intervals[st] = None

    # Build StageReconstruction list with interval ordering
    stage_results: list[StageReconstruction] = []
    prev_interval: TimeInterval | None = None
    prev_status: str | None = None
    prev_stage_name: str | None = None

    for idx, st in enumerate(tmpl.stages):
        cur_evs = stage_events[st]
        cur_claims = stage_claims[st]
        cur_interval = stage_intervals[st]

        is_supported = len(cur_evs) > 0 or len(cur_claims) > 0
        cur_status = "SUPPORTED" if is_supported else "GAP"

        # Determine interval relationship to previous stage
        if idx == 0:
            rel = "FIRST_STAGE"
        elif prev_status == "GAP" or cur_status == "GAP" or prev_interval is None or cur_interval is None:
            rel = "GAP_DETECTED"
        else:
            # Rigorous interval arithmetic via TimeInterval
            if prev_interval.definitely_before(cur_interval):
                rel = "PRECEDES"
            elif prev_interval.overlaps(cur_interval):
                # Overlapping intervals must not be asserted as definite precedence!
                rel = "CONCURRENT_OR_OVERLAPPING"
                for ev in cur_evs:
                    ev["chronology_uncertainty"]["has_uncertainty"] = True
                    if ev["chronology_uncertainty"]["ordering_certainty"] == "DEFINITE":
                        ev["chronology_uncertainty"]["ordering_certainty"] = "CONCURRENT_OR_OVERLAPPING"
            elif prev_interval.definitely_after(cur_interval):
                rel = "OUT_OF_ORDER"
                out_of_order_entry = {
                    "type": "CHRONOLOGICAL_STAGE_OUT_OF_ORDER",
                    "previous_stage": prev_stage_name,
                    "current_stage": st,
                    "previous_window": {"lo": prev_interval.lo.isoformat() + "Z", "hi": prev_interval.hi.isoformat() + "Z"},
                    "current_window": {"lo": cur_interval.lo.isoformat() + "Z", "hi": cur_interval.hi.isoformat() + "Z"},
                    "description": (
                        f"Stage '{st}' occurred definitely before prerequisite stage '{prev_stage_name}'."
                    ),
                }
                all_contradictions.append(out_of_order_entry)
                for ev in cur_evs:
                    ev["contradictions"].append(out_of_order_entry)
            else:
                rel = "UNPROVEN"

        window_dict = None
        if cur_interval is not None:
            window_dict = {
                "lo": cur_interval.lo.isoformat() + "Z",
                "hi": cur_interval.hi.isoformat() + "Z",
            }

        stage_rel_ids = sorted({
            rid
            for ev in cur_evs
            for rid in ev.get("relationship_ids", [])
        })
        stage_contradictions = [
            c for ev in cur_evs for c in ev.get("contradictions", [])
        ]
        stage_uncertainty = {
            "has_missing_timestamps": any(ev.get("event_time_utc") is None for ev in cur_evs),
            "has_uncertain_intervals": any(
                ev.get("chronology_uncertainty", {}).get("has_uncertainty", False) for ev in cur_evs
            ),
            "relationship_to_previous": rel,
        }

        stage_results.append(
            StageReconstruction(
                stage_name=st,
                status=cur_status,
                time_window=window_dict,
                relationship_to_previous=rel,
                claims=cur_claims,
                raw_events=cur_evs,
                relationship_ids=stage_rel_ids,
                contradictions=stage_contradictions,
                chronology_uncertainty=stage_uncertainty,
            )
        )

        prev_interval = cur_interval
        prev_status = cur_status
        prev_stage_name = st

    # Build deterministic flat timeline_events across all unique case events
    def _timeline_sort_key(ev: Mapping[str, Any]) -> tuple[int, str, str, str]:
        dt = _parse_utc_datetime(ev.get("event_time_utc") or ev.get("timestamp"))
        if dt is None:
            return (1, "9999-12-31T23:59:59Z", "9999-12-31T23:59:59Z", str(ev.get("event_id") or ""))
        src = str(ev.get("source") or "unknown")
        iv = effective_interval(dt, clocks.get(src, NO_CLOCK_ERROR))
        return (0, iv.lo.isoformat(), iv.hi.isoformat(), str(ev.get("event_id") or ""))

    timeline_events = sorted(ordered_unique_events, key=_timeline_sort_key)

    # Check pairwise interval overlaps among adjacent timeline events
    for i in range(len(timeline_events) - 1):
        ev_cur = timeline_events[i]
        ev_nxt = timeline_events[i + 1]
        dt_cur = _parse_utc_datetime(ev_cur.get("event_time_utc") or ev_cur.get("timestamp"))
        dt_nxt = _parse_utc_datetime(ev_nxt.get("event_time_utc") or ev_nxt.get("timestamp"))
        if dt_cur is not None and dt_nxt is not None:
            iv_cur = effective_interval(dt_cur, clocks.get(str(ev_cur.get("source") or "unknown"), NO_CLOCK_ERROR))
            iv_nxt = effective_interval(dt_nxt, clocks.get(str(ev_nxt.get("source") or "unknown"), NO_CLOCK_ERROR))
            if iv_cur.overlaps(iv_nxt):
                for target_ev in (ev_cur, ev_nxt):
                    target_ev["chronology_uncertainty"]["has_uncertainty"] = True
                    if target_ev["chronology_uncertainty"]["ordering_certainty"] == "DEFINITE":
                        target_ev["chronology_uncertainty"]["ordering_certainty"] = "CONCURRENT_OR_OVERLAPPING"

    chronology_uncertainties: list[dict[str, Any]] = [
        {
            "kind": "EVENT_TIMESTAMP_UNCERTAINTY",
            "event_id": ev["event_id"],
            "evidence_id": ev.get("evidence_id"),
            "source_locator": ev.get("source_locator"),
            **ev["chronology_uncertainty"],
        }
        for ev in timeline_events
        if ev.get("chronology_uncertainty", {}).get("has_uncertainty")
    ]
    for st_res in stage_results:
        if st_res.relationship_to_previous in ("OUT_OF_ORDER", "CONCURRENT_OR_OVERLAPPING"):
            chronology_uncertainties.append({
                "kind": f"STAGE_{st_res.relationship_to_previous}",
                "stage_name": st_res.stage_name,
                "relationship_to_previous": st_res.relationship_to_previous,
                "time_window": st_res.time_window,
            })

    missing_timestamp_events = [
        ev for ev in timeline_events if ev.get("event_time_utc") is None
    ]
    conflicting_timestamp_events = [
        ev for ev in timeline_events
        if ev.get("chronology_uncertainty", {}).get("has_timestamp_conflict")
    ]
    all_evidence_ids = sorted({
        str(ev["evidence_id"])
        for ev in timeline_events
        if ev.get("evidence_id")
    })

    # Background activity (events not assigned to this hypothesis)
    all_case_event_ids = {e["event_id"] for e in ordered_unique_events if "event_id" in e}
    background_ids = sorted(all_case_event_ids - hyp_assigned_event_ids)

    # Residual H0 event IDs
    res_h0_ids = sorted(h0_event_ids) if h0_event_ids is not None else background_ids

    # Build narrative summary text
    supported_stages = [s.stage_name for s in stage_results if s.status == "SUPPORTED"]
    gap_stages = [s.stage_name for s in stage_results if s.status == "GAP"]
    summary = (
        f"Reconstruction for {hyp_name} ({hyp_id}) [{hyp_status}]: "
        f"{len(supported_stages)} supported stages ({', '.join(supported_stages) or 'none'}), "
        f"{len(gap_stages)} gaps ({', '.join(gap_stages) or 'none'}). "
        f"{len(hyp_assigned_event_ids)} events directly linked to hypothesis stages; "
        f"{len(background_ids)} background events."
    )

    all_rel_ids = sorted({r["relationship_id"] for r in norm_relationships})

    return NarrativeReconstruction(
        hypothesis_id=hyp_id,
        hypothesis_name=hyp_name,
        status=hyp_status,
        stages=stage_results,
        background_activity_count=len(background_ids),
        background_activity_event_ids=background_ids,
        residual_h0_count=len(res_h0_ids),
        residual_h0_event_ids=res_h0_ids,
        narrative_summary=summary,
        case_id=resolved_case_id,
        analysis_run_id=resolved_run_id,
        timeline_events=timeline_events,
        evidence_ids=all_evidence_ids,
        relationship_ids=all_rel_ids,
        contradictions=all_contradictions,
        chronology_uncertainties=chronology_uncertainties,
        missing_timestamp_event_ids=sorted(missing_timestamp_event_ids),
        missing_timestamp_events=missing_timestamp_events,
        conflicting_timestamp_events=conflicting_timestamp_events,
        duplicate_event_ids=sorted(duplicate_event_ids),
    )
