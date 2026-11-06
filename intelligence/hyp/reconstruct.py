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
    load_templates,
)


@dataclass
class StageReconstruction:
    stage_name: str
    status: str  # "SUPPORTED" or "GAP"
    time_window: dict[str, str] | None = None  # {"lo": iso, "hi": iso}
    relationship_to_previous: str = "FIRST_STAGE"  # PRECEDES, CONCURRENT_OR_OVERLAPPING, OUT_OF_ORDER, UNPROVEN, GAP_DETECTED
    claims: list[dict[str, Any]] = field(default_factory=list)
    raw_events: list[dict[str, Any]] = field(default_factory=list)

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

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["stages"] = [s.to_dict() for s in self.stages]
        return d


def _parse_utc_datetime(val: Any) -> datetime | None:
    if isinstance(val, datetime):
        return val.astimezone(timezone.utc).replace(tzinfo=None) if val.tzinfo else val
    if isinstance(val, str):
        try:
            dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt
        except ValueError:
            return None
    return None


def reconstruct_narrative(
    hypothesis: RankedHypothesis | HypothesisTemplate | str,
    claims: Sequence[Any],
    events: Sequence[Mapping[str, Any]],
    source_clocks: Mapping[str, SourceClock] | None = None,
    h0_event_ids: Sequence[str] | None = None,
    templates: Sequence[HypothesisTemplate] | None = None,
) -> NarrativeReconstruction:
    """Reconstruct a hypothesis into chronological stages with interval analysis.

    Args:
        hypothesis: RankedHypothesis object, HypothesisTemplate, or hypothesis ID string ("H1", "H2", "H3").
        claims: Evaluated claims from the analysis run.
        events: Ingested case events.
        source_clocks: Optional SourceClock uncertainties.
        h0_event_ids: Optional precomputed H0 residual event IDs.
        templates: Optional explicit hypothesis templates (e.g. preserved from run snapshot).
                   When provided, templates are NEVER loaded from disk.

    Returns:
        NarrativeReconstruction computed view.
    """
    clocks = dict(source_clocks) if source_clocks is not None else load_source_clocks()
    events_by_id = {e["event_id"]: e for e in events if "event_id" in e}

    # Resolve template: prefer explicit templates, avoiding silent disk loads on historical replay
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

    # Map template items to stages
    # stage -> list of matching claims and events
    stage_claims: dict[str, list[dict[str, Any]]] = {st: [] for st in tmpl.stages}
    stage_events: dict[str, list[dict[str, Any]]] = {st: [] for st in tmpl.stages}
    stage_intervals: dict[str, TimeInterval | None] = {st: None for st in tmpl.stages}

    # Normalize claims
    dict_claims: list[dict[str, Any]] = []
    for c in claims:
        if hasattr(c, "to_dict"):
            dict_claims.append(c.to_dict())
        elif isinstance(c, dict):
            dict_claims.append(c)
        else:
            dict_claims.append({
                "claim_id": getattr(c, "claim_id", None),
                "type": getattr(c, "type", None),
                "params": getattr(c, "params", {}),
                "status": getattr(c, "status", "ASSERTED"),
                "grade": getattr(c, "grade", "B"),
                "edges": getattr(c, "edges", []),
            })

    # Associate claims with stages based on template requires & expects
    relevant_items = tmpl.requires + tmpl.expects
    hyp_assigned_event_ids: set[str] = set()

    for item in relevant_items:
        matching = [
            c for c in dict_claims
            if c.get("type") == item.claim_type and c.get("status") in ("ASSERTED", "CORROBORATED")
        ]
        if item.params:
            filtered = []
            for c in matching:
                c_p = c.get("params") or {}
                if all(c_p.get(k) == v for k, v in item.params.items()):
                    filtered.append(c)
            matching = filtered

        for c in matching:
            if c not in stage_claims[item.stage]:
                stage_claims[item.stage].append(c)

            # Extract referenced events
            edges = c.get("edges") or []
            for edge in edges:
                ref_kind = getattr(edge, "ref_kind", None) or (edge.get("ref_kind") if isinstance(edge, dict) else None)
                ref_id = getattr(edge, "ref_id", None) or (edge.get("ref_id") if isinstance(edge, dict) else None)
                if ref_kind == "event" and ref_id in events_by_id:
                    ev = events_by_id[ref_id]
                    if ev not in stage_events[item.stage]:
                        stage_events[item.stage].append(ev)
                    hyp_assigned_event_ids.add(ref_id)

    # Compute TimeInterval for each stage
    for st in tmpl.stages:
        evs = stage_events[st]
        intervals: list[TimeInterval] = []
        for e in evs:
            dt = _parse_utc_datetime(e.get("timestamp"))
            if dt is not None:
                src = e.get("source") or "unknown"
                clock = clocks.get(src, NO_CLOCK_ERROR)
                intervals.append(effective_interval(dt, clock))

        if intervals:
            lo = min(i.lo for i in intervals)
            hi = max(i.hi for i in intervals)
            stage_intervals[st] = TimeInterval(lo, hi)
        else:
            stage_intervals[st] = None

    # Build StageReconstruction list with interval ordering
    stage_results: list[StageReconstruction] = []
    prev_interval: TimeInterval | None = None
    prev_status: str | None = None

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
            elif prev_interval.definitely_after(cur_interval):
                rel = "OUT_OF_ORDER"
            else:
                rel = "UNPROVEN"

        window_dict = None
        if cur_interval is not None:
            window_dict = {
                "lo": cur_interval.lo.isoformat() + "Z",
                "hi": cur_interval.hi.isoformat() + "Z",
            }

        stage_results.append(
            StageReconstruction(
                stage_name=st,
                status=cur_status,
                time_window=window_dict,
                relationship_to_previous=rel,
                claims=cur_claims,
                raw_events=cur_evs,
            )
        )

        prev_interval = cur_interval
        prev_status = cur_status

    # Background activity (events not assigned to this hypothesis)
    all_case_event_ids = {e["event_id"] for e in events if "event_id" in e}
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
    )
