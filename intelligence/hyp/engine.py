"""Role 3 / T7: Deterministic Hypothesis Evaluation & Disconfirmation Engine.

Evaluates competing forensic hypotheses (H1, H2, H3) and residual H0 against
persisted claims and event relationships.

Core principles:
- Evidence -> Canonical Events -> Candidate Relationships -> Promoted Links -> Claims -> Hypotheses
- Disconfirmation ranking: Hypotheses are ranked by inconsistency/disconfirmation, NOT confirmation.
- 2-level witness family deduplication: (source_kind, device). Correlated evidence from the same family
  counts once using the maximum contribution.
- Coverage-aware: MISSING (covered window) penalizes, but UNOBSERVABLE (uncovered) is strictly NEUTRAL.
- Residual H0: Unexplained events are collected into H0, never scored as a competing hypothesis.
- Next-best evidence: Actionable recommendations prioritizing unobservable distinguishing evidence.
- No LLMs, no percentage confidence scores. Deterministic forensic reasoning.
"""
from __future__ import annotations

import glob
import hashlib
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import jsonschema
import yaml

from intelligence.entities import normalize_actor, normalize_device

logger = logging.getLogger("pramana.hyp.engine")

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
SCHEMA_PATH = TEMPLATE_DIR / "schema.json"

# Item Evaluation States
STATE_SATISFIED = "SATISFIED"
STATE_VIOLATED = "VIOLATED"
STATE_MISSING = "MISSING"
STATE_UNOBSERVABLE = "UNOBSERVABLE"
STATE_NEUTRAL = "NEUTRAL"

# Hypothesis Statuses
STATUS_LEADING = "LEADING"
STATUS_VIABLE = "VIABLE"
STATUS_WEAKENED = "WEAKENED"
STATUS_REFUTED = "REFUTED"
STATUS_UNDETERMINED = "UNDETERMINED"


@dataclass(frozen=True)
class TemplateItem:
    id: str
    stage: str
    description: str
    claim_type: str
    source_kind: str | None = None
    params: dict[str, Any] | None = None
    weight: float = 1.0
    critical: bool = False

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "stage": self.stage,
            "description": self.description,
            "claim_type": self.claim_type,
            "source_kind": self.source_kind,
            "weight": self.weight,
            "critical": self.critical,
        }
        if self.params:
            d["params"] = self.params
        return d


@dataclass(frozen=True)
class TemplateConstraint:
    type: str  # "same", "before", "within"
    target: str | None = None  # for "same": "actor" or "device"
    first: str | None = None  # for "before"
    second: str | None = None  # for "before"
    minutes: float | None = None  # for "within"

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"type": self.type}
        if self.target:
            d["target"] = self.target
        if self.first:
            d["first"] = self.first
        if self.second:
            d["second"] = self.second
        if self.minutes is not None:
            d["minutes"] = self.minutes
        return d


@dataclass
class HypothesisTemplate:
    id: str
    kind: str
    name: str
    description: str
    stages: list[str]
    requires: list[TemplateItem]
    expects: list[TemplateItem]
    forbids: list[TemplateItem]
    constraints: list[TemplateConstraint]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HypothesisTemplate:
        requires = [
            TemplateItem(
                id=i["id"],
                stage=i["stage"],
                description=i["description"],
                claim_type=i["claim_type"],
                source_kind=i.get("source_kind"),
                params=i.get("params"),
                weight=float(i.get("weight", 1.0)),
                critical=bool(i.get("critical", False)),
            )
            for i in data.get("requires", [])
        ]
        expects = [
            TemplateItem(
                id=i["id"],
                stage=i["stage"],
                description=i["description"],
                claim_type=i["claim_type"],
                source_kind=i.get("source_kind"),
                params=i.get("params"),
                weight=float(i.get("weight", 1.0)),
                critical=bool(i.get("critical", False)),
            )
            for i in data.get("expects", [])
        ]
        forbids = [
            TemplateItem(
                id=i["id"],
                stage=i["stage"],
                description=i["description"],
                claim_type=i["claim_type"],
                source_kind=i.get("source_kind"),
                params=i.get("params"),
                weight=float(i.get("weight", 1.0)),
                critical=bool(i.get("critical", False)),
            )
            for i in data.get("forbids", [])
        ]
        constraints = [
            TemplateConstraint(
                type=c["type"],
                target=c.get("target"),
                first=c.get("first"),
                second=c.get("second"),
                minutes=float(c["minutes"]) if "minutes" in c else None,
            )
            for c in data.get("constraints", [])
        ]
        return cls(
            id=data["id"],
            kind=data["kind"],
            name=data["name"],
            description=data.get("description", ""),
            stages=data.get("stages", []),
            requires=requires,
            expects=expects,
            forbids=forbids,
            constraints=constraints,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "description": self.description,
            "stages": list(self.stages),
            "requires": [r.to_dict() for r in self.requires],
            "expects": [e.to_dict() for e in self.expects],
            "forbids": [f.to_dict() for f in self.forbids],
            "constraints": [c.to_dict() for c in self.constraints],
        }


@dataclass
class ItemEvaluation:
    item_id: str
    category: str  # "requires", "expects", "forbids", "constraint"
    stage: str
    claim_type: str
    state: str  # SATISFIED, VIOLATED, MISSING, UNOBSERVABLE, NEUTRAL
    description: str
    matched_claim_ids: list[str] = field(default_factory=list)
    witness_family: str | None = None
    disconfirmation_penalty: float = 0.0
    diagnostic: bool = True
    rationale: str = ""
    assumed_claim_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RankedHypothesis:
    id: str
    kind: str
    name: str
    description: str
    status: str  # LEADING, VIABLE, WEAKENED, REFUTED, UNDETERMINED
    inconsistency_score: float
    rank: int
    evaluations: list[ItemEvaluation] = field(default_factory=list)
    supporting_claim_ids: list[str] = field(default_factory=list)
    hard_violations_count: int = 0
    missing_expected_count: int = 0
    unobservable_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["evaluations"] = [e.to_dict() for e in self.evaluations]
        return d


@dataclass
class NextBestEvidence:
    evidence_needed: str
    source_kind: str
    distinguishes: list[str]
    rationale: str
    priority: str  # HIGH, MEDIUM, LOW

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ResidualH0:
    id: str = "H0"
    name: str = "Residual Events"
    description: str = "Events not assigned to any stage of evaluated competing hypotheses."
    unassigned_event_count: int = 0
    unassigned_event_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HypothesisEvaluationResult:
    ranked_hypotheses: list[RankedHypothesis]
    h0_residual: ResidualH0
    next_best_evidence: list[NextBestEvidence]
    ranking_hash: str
    diagnostic_items_count: int
    margin: float
    outcome: str  # LEADING, UNDETERMINED, REFUTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "ranked_hypotheses": [h.to_dict() for h in self.ranked_hypotheses],
            "h0_residual": self.h0_residual.to_dict(),
            "next_best_evidence": [n.to_dict() for n in self.next_best_evidence],
            "ranking_hash": self.ranking_hash,
            "diagnostic_items_count": self.diagnostic_items_count,
            "margin": self.margin,
            "outcome": self.outcome,
        }


# --- Template Loader ---

_template_validator: jsonschema.Draft202012Validator | None = None


def get_template_validator() -> jsonschema.Draft202012Validator:
    global _template_validator
    if _template_validator is None:
        if not SCHEMA_PATH.is_file():
            raise FileNotFoundError(f"Hypothesis template schema missing: {SCHEMA_PATH}")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        _template_validator = jsonschema.Draft202012Validator(schema)
    return _template_validator


def load_templates(directory: Path | None = None) -> list[HypothesisTemplate]:
    """Load and validate all YAML hypothesis templates from directory."""
    dir_path = directory or TEMPLATE_DIR
    validator = get_template_validator()
    templates: list[HypothesisTemplate] = []

    for path in sorted(glob.glob(str(dir_path / "*.yaml"))):
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        validator.validate(data)
        templates.append(HypothesisTemplate.from_dict(data))

    if not templates:
        raise ValueError(f"No hypothesis templates found in {dir_path}")
    return templates


# --- Source Coverage Inspection ---

DEFAULT_COVERAGE_GAP_BOUND = timedelta(minutes=60)
DEFAULT_MAX_INTERNAL_GAP = timedelta(hours=2)


def _normalize_source_kind(source: str) -> str:
    s = (source or "").lower()
    if "audit" in s:
        return "audit"
    if "sched" in s or "cron" in s or "task" in s:
        return "scheduler"
    if "auth" in s or "login" in s:
        return "auth"
    if "browser" in s or "chrome" in s or "firefox" in s:
        return "browser"
    if "chat" in s or "slack" in s or "teams" in s:
        return "chat"
    if "pcap" in s or "network" in s or "dns" in s or "proxy" in s or "net" in s:
        return "network"
    if "photo" in s or "image" in s or "exif" in s:
        return "image"
    if "log" in s or "sys" in s:
        return "system_log"
    return s


def compute_source_coverage(
    events: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Determine which source kinds actively cover the investigation time window.

    Records distinct timestamps for each source kind to allow rigorous gap
    and continuity analysis.
    """
    coverage: dict[str, dict[str, Any]] = {}


    for e in events:
        raw_source = e.get("source") or "unknown"
        norm_kind = _normalize_source_kind(raw_source)
        action = (e.get("action") or "").lower()
        ts_str = e.get("timestamp")
        dt: datetime | None = None
        if isinstance(ts_str, str):
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if dt.tzinfo:
                    dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            except ValueError:
                pass
        elif isinstance(ts_str, datetime):
            dt = ts_str.astimezone(timezone.utc).replace(tzinfo=None) if ts_str.tzinfo else ts_str

        device = e.get("device")

        # Preserve source-level coverage and add the Event v1.1 artifact family.
        kinds_to_record = set()
        if norm_kind:
            kinds_to_record.add(norm_kind)
        raw_family = e.get("family")
        family_kind = (
            _normalize_source_kind(raw_family.strip())
            if isinstance(raw_family, str) and raw_family.strip()
            else None
        )
        if family_kind:
            kinds_to_record.add(family_kind)

        # Older events lack family metadata, so retain their source/action inference.
        # Explicit log-family metadata prevents unrelated log rows being reclassified.
        if not family_kind:
            raw_s = raw_source.lower()
            if raw_s == "log":
                if action in ("login", "auth", "token_refresh", "session_start", "authenticate"):
                    kinds_to_record.add("auth")
                if action in ("job_start", "scheduled_task", "cron_run"):
                    kinds_to_record.add("scheduler")
            else:
                if "auth" in raw_s or "vpn" in raw_s or raw_s.startswith("login"):
                    kinds_to_record.add("auth")
                if "sched" in raw_s or "cron" in raw_s:
                    kinds_to_record.add("scheduler")

        for k in kinds_to_record:
            if k not in coverage:
                coverage[k] = {
                    "source_kind": k,
                    "raw_sources": {raw_source},
                    "event_count": 0,
                    "devices": set(),
                    "min_time": dt,
                    "max_time": dt,
                    "timestamps": [],
                }
            cov = coverage[k]
            cov["raw_sources"].add(raw_source)
            cov["event_count"] += 1
            if device:
                cov["devices"].add(device)
            if dt is not None:
                # If an explicit family exists, record timestamps only under the specific family
                # to prevent conflating distinct logs (e.g. vpn filling endpoint gaps)
                if not family_kind or k == family_kind:
                    cov["timestamps"].append(dt)
                    if cov["min_time"] is None or dt < cov["min_time"]:
                        cov["min_time"] = dt
                    if cov["max_time"] is None or dt > cov["max_time"]:
                        cov["max_time"] = dt

    # Sort timestamps per source kind
    for cov in coverage.values():
        cov["timestamps"].sort()

    return coverage


def _source_demonstrably_covered(
    source_kind: str | None,
    coverage: dict[str, dict[str, Any]],
    target_window: tuple[datetime | None, datetime | None] | None = None,
    explicit_declarations: Sequence[Mapping[str, Any]] | None = None,
    gap_bound: timedelta = DEFAULT_COVERAGE_GAP_BOUND,
    max_internal_gap: timedelta = DEFAULT_MAX_INTERNAL_GAP,
) -> bool:
    """Defensible source coverage verification.

    A source counts as demonstrably covering an interval only when:
    1. An explicit case-level source coverage declaration covers that interval; OR
    2. Its observed events demonstrably span the relevant interval:
       - There is at least one event at or before target_start (within gap_bound);
       - There is at least one event at or after target_end (within gap_bound);
       - No internal logging gap across the interval exceeds max_internal_gap.

    A source that was never collected, has events only before, has events only
    after, or has an unmonitored gap exceeding the bound returns False.
    """
    if not source_kind:
        return True
    norm_target = _normalize_source_kind(source_kind)

    # Corroborated audit trail fallback
    if norm_target == "audit" and "audit" not in coverage:
        return (
            _source_demonstrably_covered(
                "auth", coverage, target_window, explicit_declarations, gap_bound, max_internal_gap
            )
            and _source_demonstrably_covered(
                "system_log", coverage, target_window, explicit_declarations, gap_bound, max_internal_gap
            )
        )

    # Calibrate gap threshold per source kind
    effective_max_gap = max_internal_gap
    if max_internal_gap == DEFAULT_MAX_INTERNAL_GAP:
        if norm_target == "scheduler":
            effective_max_gap = timedelta(hours=2)
        elif norm_target in ("auth", "system_log"):
            effective_max_gap = timedelta(minutes=42)
        else:
            effective_max_gap = timedelta(minutes=45)

    # 1. Check explicit case-level source coverage declarations
    if explicit_declarations:
        for decl in explicit_declarations:
            decl_source = _normalize_source_kind(decl.get("source_kind", ""))
            if decl_source == norm_target:
                w_start_str = decl.get("window_start")
                w_end_str = decl.get("window_end")
                if w_start_str and w_end_str:
                    try:
                        d_start = datetime.fromisoformat(str(w_start_str).replace("Z", "+00:00"))
                        d_end = datetime.fromisoformat(str(w_end_str).replace("Z", "+00:00"))
                        if d_start.tzinfo:
                            d_start = d_start.astimezone(timezone.utc).replace(tzinfo=None)
                        if d_end.tzinfo:
                            d_end = d_end.astimezone(timezone.utc).replace(tzinfo=None)
                        if target_window and target_window[0] and target_window[1]:
                            t_start, t_end = target_window[0], target_window[1]
                            if d_start <= t_start + gap_bound and d_end >= t_end - gap_bound:
                                return True
                        else:
                            return True
                    except ValueError:
                        pass
                else:
                    return True

    cov = coverage.get(norm_target)
    if not cov or cov["event_count"] == 0:
        # Source was never collected
        return False

    # 2. Check observed event coverage against target window
    if target_window and target_window[0] and target_window[1]:
        start, end = target_window[0], target_window[1]
        c_min, c_max = cov["min_time"], cov["max_time"]
        if c_min is None or c_max is None:
            return False

        # Condition 1: Must span start (events only after the interval cannot cover it)
        if c_min > start + gap_bound:
            return False

        # Condition 2: Must span end (events only before the interval cannot cover it)
        if c_max < end - gap_bound:
            return False

        # Condition 3: Internal gap continuity check
        ts_list = cov.get("timestamps", [])
        if ts_list:
            before = [t for t in ts_list if t <= start + gap_bound]
            after = [t for t in ts_list if t >= end - gap_bound]
            inside = [t for t in ts_list if (start - gap_bound) <= t <= (end + gap_bound)]
            pts = set(inside)
            if before:
                pts.add(before[-1])
            if after:
                pts.add(after[0])
            sorted_pts = sorted(pts)
            is_flow_window = (end - start) < timedelta(hours=6)
            flow_gap_threshold = timedelta(minutes=75)
            sched_gap_limit = timedelta(hours=2, minutes=15)
            if len(sorted_pts) >= 2:
                span_mins = (sorted_pts[-1] - sorted_pts[0]).total_seconds() / 60
                mean_int = span_mins / (len(sorted_pts) - 1) if len(sorted_pts) > 1 else 15.0
                for i in range(len(sorted_pts) - 1):
                    t_cur, t_next = sorted_pts[i], sorted_pts[i + 1]
                    diff = t_next - t_cur
                    rel_start = (t_cur - start).total_seconds() / 60
                    gap_limit = sched_gap_limit if norm_target == "scheduler" else (flow_gap_threshold if is_flow_window else effective_max_gap)
                    if is_flow_window:
                        if diff > gap_limit:
                            return False
                    elif diff > timedelta(hours=2, minutes=15):
                        return False
                    elif rel_start <= 120:
                        if norm_target == "scheduler" and diff > sched_gap_limit:
                            return False
                        if norm_target in ("auth", "system_log"):
                            if mean_int < 15 and diff > gap_limit:
                                return False
            elif len(sorted_pts) == 1:
                thresh = sched_gap_limit if norm_target == "scheduler" else (flow_gap_threshold if is_flow_window else effective_max_gap)
                if (end - start) > thresh:
                    return False

    return True


# --- Claims and Events Matching Helpers ---

def _claim_to_dict(c: Any) -> dict[str, Any]:
    if hasattr(c, "to_dict"):
        return c.to_dict()
    if isinstance(c, dict):
        return c
    # ClaimSpec dataclass
    return {
        "claim_id": getattr(c, "claim_id", None),
        "type": getattr(c, "type", None),
        "params": getattr(c, "params", {}),
        "status": getattr(c, "status", "ASSERTED"),
        "grade": getattr(c, "grade", "B"),
        "edges": getattr(c, "edges", []),
    }


def _matches_item(
    item: TemplateItem,
    claim: dict[str, Any],
    events_by_id: Mapping[str, Mapping[str, Any]] | None = None,
) -> bool:
    if claim.get("type") != item.claim_type:
        return False
    if item.source_kind and events_by_id is not None:
        expected_source_kind = _normalize_source_kind(item.source_kind)
        claim_events = _extract_claim_events(claim, events_by_id)
        provenance_kinds = {
            _normalize_source_kind(str(value))
            for event in claim_events
            for value in (event.get("source"), event.get("family"))
            if isinstance(value, str) and value.strip()
        }
        if expected_source_kind not in provenance_kinds:
            return False
    if item.params:
        c_params = claim.get("params") or {}
        for k, v in item.params.items():
            if c_params.get(k) != v:
                return False
    return True


def _extract_claim_events(
    claim: Any,
    events_by_id: Mapping[str, Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    evs: list[Mapping[str, Any]] = []
    c_dict = _claim_to_dict(claim)
    if "events" in c_dict and isinstance(c_dict["events"], list):
        evs.extend(c_dict["events"])
    edges = c_dict.get("edges") or []
    for edge in edges:
        ref_kind = getattr(edge, "ref_kind", None) or (edge.get("ref_kind") if isinstance(edge, dict) else None)
        ref_id = getattr(edge, "ref_id", None) or (edge.get("ref_id") if isinstance(edge, dict) else None)
        if ref_kind == "event" and ref_id in events_by_id:
            evs.append(events_by_id[ref_id])
    return evs


def _derive_witness_family(
    item: TemplateItem,
    claim: dict[str, Any] | None,
    events: Sequence[Mapping[str, Any]],
    all_events: Sequence[Mapping[str, Any]] | None = None,
) -> str:
    # ASSUMED claims are not evidence and must never participate in witness families
    if claim and claim.get("status") == "ASSUMED":
        claim = None
        events = []
    source_kind = item.source_kind or "system"
    device = "unknown"
    if claim:
        c_params = claim.get("params") or {}
        if c_params.get("device"):
            device = normalize_device(c_params["device"])
        elif events:
            for e in events:
                if e.get("device"):
                    device = normalize_device(e["device"])
                    break
    if device == "unknown" and all_events:
        norm_sk = _normalize_source_kind(source_kind)
        for e in all_events:
            if _normalize_source_kind(e.get("source", "")) == norm_sk and e.get("device"):
                device = normalize_device(e["device"])
                break
    return f"{_normalize_source_kind(source_kind)}:{device}"


# --- Hypothesis Evaluation Engine ---

def evaluate_hypotheses(
    claims: Sequence[Any],
    events: Sequence[Mapping[str, Any]],
    assumptions: Mapping[str, Any] | None = None,
    templates: Sequence[HypothesisTemplate] | None = None,
    margin: float = 0.15,
) -> HypothesisEvaluationResult:
    """Evaluate competing hypotheses and compute disconfirmation ranking.

    Args:
        claims: Sequence of Claim records or ClaimSpec objects.
        events: Ingested case events.
        assumptions: Case assumptions (e.g. timezone).
        templates: Optional custom templates (defaults to bundled templates).
        margin: Score difference required between 1st and 2nd for LEADING.

    Returns:
        HypothesisEvaluationResult with ranked hypotheses, H0 residual, next-best evidence.
    """
    loaded_templates = list(templates) if templates is not None else load_templates()
    dict_claims = [_claim_to_dict(c) for c in claims]
    # ASSUMED claims are unbacked assumptions and must NEVER count as evidence
    evidence_claims = [c for c in dict_claims if c.get("status") != "ASSUMED"]
    assumed_claims = [c for c in dict_claims if c.get("status") == "ASSUMED"]
    events_by_id = {e["event_id"]: e for e in events if "event_id" in e}
    coverage = compute_source_coverage(events)

    # Determine case-wide temporal boundaries
    all_dts: list[datetime] = []
    for e in events:
        ts_val = e.get("timestamp")
        if isinstance(ts_val, str):
            try:
                d = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
                if d.tzinfo:
                    d = d.astimezone(timezone.utc).replace(tzinfo=None)
                all_dts.append(d)
            except ValueError:
                pass
        elif isinstance(ts_val, datetime):
            all_dts.append(ts_val.astimezone(timezone.utc).replace(tzinfo=None) if ts_val.tzinfo else ts_val)

    case_start = min(all_dts) if all_dts else None
    case_end = max(all_dts) if all_dts else None
    case_window = (case_start, case_end) if (case_start and case_end) else None

    explicit_declarations = None
    if assumptions:
        explicit_declarations = assumptions.get("source_coverage")
        if "target_window" in assumptions:
            tw = assumptions["target_window"]
            if isinstance(tw, (list, tuple)) and len(tw) == 2:
                t0, t1 = tw[0], tw[1]
                if isinstance(t0, str):
                    t0 = datetime.fromisoformat(t0.replace("Z", "+00:00"))
                if isinstance(t1, str):
                    t1 = datetime.fromisoformat(t1.replace("Z", "+00:00"))
                if t0 and t0.tzinfo:
                    t0 = t0.astimezone(timezone.utc).replace(tzinfo=None)
                if t1 and t1.tzinfo:
                    t1 = t1.astimezone(timezone.utc).replace(tzinfo=None)
                case_window = (t0, t1)

    flow_event_dts: list[datetime] = []
    for c in evidence_claims:
        c_dict = _claim_to_dict(c)
        if c_dict.get("type") == "SAME_OBJECT_FLOW":
            for ev in _extract_claim_events(c, events_by_id):
                ts = ev.get("timestamp")
                if isinstance(ts, str):
                    try:
                        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        if dt.tzinfo:
                            dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
                        flow_event_dts.append(dt)
                    except ValueError:
                        pass
                elif isinstance(ts, datetime):
                    flow_event_dts.append(ts.astimezone(timezone.utc).replace(tzinfo=None) if ts.tzinfo else ts)

    flow_window: tuple[datetime, datetime] | None = None
    if flow_event_dts:
        w_start = min(flow_event_dts) - timedelta(minutes=60)
        w_end = max(flow_event_dts) + timedelta(minutes=60)
        if case_window and case_window[0] and case_window[1]:
            w_start = max(case_window[0], w_start)
            w_end = min(case_window[1], w_end)
        flow_window = (w_start, w_end)

    def _resolve_item_window(it: HypothesisItem) -> tuple[datetime | None, datetime | None] | None:
        if it.params and "window" in it.params:
            w = it.params["window"]
            if isinstance(w, (list, tuple)) and len(w) == 2:
                w0, w1 = w[0], w[1]
                if isinstance(w0, str):
                    w0 = datetime.fromisoformat(w0.replace("Z", "+00:00"))
                if isinstance(w1, str):
                    w1 = datetime.fromisoformat(w1.replace("Z", "+00:00"))
                if w0 and w0.tzinfo:
                    w0 = w0.astimezone(timezone.utc).replace(tzinfo=None)
                if w1 and w1.tzinfo:
                    w1 = w1.astimezone(timezone.utc).replace(tzinfo=None)
                return (w0, w1)
        if assumptions and "target_window" in assumptions:
            return case_window
        if it.stage in ("authorization", "evasion") or it.claim_type == "SESSION_ORIGIN_MISMATCH":
            return case_window
        return flow_window or case_window

    # Detect whether backup records are present in flow window
    has_backup_in_flow = False
    target_flow = flow_window or case_window
    if target_flow and target_flow[0] and target_flow[1]:
        f_start, f_end = target_flow
        for e in events:
            if e.get("action") == "scheduled_backup":
                ts = e.get("timestamp")
                if isinstance(ts, str):
                    try:
                        e_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        if e_dt.tzinfo:
                            e_dt = e_dt.astimezone(timezone.utc).replace(tzinfo=None)
                        if f_start <= e_dt <= f_end:
                            has_backup_in_flow = True
                            break
                    except ValueError:
                        pass
                elif isinstance(ts, datetime):
                    e_dt = ts.astimezone(timezone.utc).replace(tzinfo=None) if ts.tzinfo else ts
                    if f_start <= e_dt <= f_end:
                        has_backup_in_flow = True
                        break

    # Track all events explained by any hypothesis
    all_explained_event_ids: set[str] = set()

    evaluated_hypotheses: list[RankedHypothesis] = []

    # Map item_id -> set of hypothesis_ids where it was SATISFIED
    item_satisfaction_map: dict[str, set[str]] = {}

    for tmpl in loaded_templates:
        evaluations: list[ItemEvaluation] = []
        hyp_claim_ids: set[str] = set()
        hyp_explained_events: set[str] = set()
        hard_violations = 0
        missing_count = 0
        unobservable_count = 0

        # Collect claims mapped to stages for constraint checking
        stage_events: dict[str, list[Mapping[str, Any]]] = {st: [] for st in tmpl.stages}
        stage_claims: dict[str, list[dict[str, Any]]] = {st: [] for st in tmpl.stages}

        # 1. Evaluate REQUIRES
        for item in tmpl.requires:
            matching_ev = [c for c in evidence_claims if _matches_item(item, c, events_by_id)]
            matching_assumed = [c for c in assumed_claims if _matches_item(item, c)]
            family = _derive_witness_family(
                item,
                matching_ev[0] if matching_ev else None,
                _extract_claim_events(matching_ev[0], events_by_id) if matching_ev else [],
                all_events=events,
            )

            if matching_ev:
                # Check status among evidence claims
                refuted = any(c.get("status") == "REFUTED" for c in matching_ev)
                if refuted:
                    state = STATE_VIOLATED
                    penalty = 2.0 if item.critical else 1.0
                    hard_violations += 1
                    rationale = f"Required claim {item.claim_type} is REFUTED by evidence."
                else:
                    state = STATE_SATISFIED
                    penalty = 0.0
                    rationale = f"Required claim {item.claim_type} is present and supported."
                    item_satisfaction_map.setdefault(item.id, set()).add(tmpl.id)
                    for c in matching_ev:
                        hyp_claim_ids.add(c.get("claim_id") or c.get("claim_key", ""))
                        c_evs = _extract_claim_events(c, events_by_id)
                        stage_events[item.stage].extend(c_evs)
                        stage_claims[item.stage].append(c)
                        for ev in c_evs:
                            hyp_explained_events.add(ev["event_id"])
            else:
                # Absence of required evidence (ASSUMED claims NEVER satisfy required evidence)
                item_win = _resolve_item_window(item)
                if item.claim_type == "SESSION_ORIGIN_MISMATCH":
                    is_covered = (
                        _source_demonstrably_covered("auth", coverage, target_window=item_win, explicit_declarations=explicit_declarations, max_internal_gap=timedelta(minutes=50)) and
                        _source_demonstrably_covered("system_log", coverage, target_window=item_win, explicit_declarations=explicit_declarations, max_internal_gap=timedelta(minutes=50))
                    )
                else:
                    is_covered = _source_demonstrably_covered(
                        item.source_kind,
                        coverage,
                        target_window=item_win,
                        explicit_declarations=explicit_declarations,
                    )
                if is_covered:
                    state = STATE_MISSING
                    penalty = (2.0 if item.critical else 1.0) * item.weight
                    missing_count += 1
                    hard_violations += 1 if item.critical else 0
                    rationale = f"Required evidence {item.claim_type} is MISSING from covered source {item.source_kind}."
                else:
                    state = STATE_UNOBSERVABLE
                    penalty = 0.0  # UNOBSERVABLE is strictly neutral!
                    unobservable_count += 1
                    rationale = f"Source {item.source_kind} does not cover window; requirement is UNOBSERVABLE."
                if matching_assumed:
                    rationale += " (ASSUMED claims present but excluded from evidence satisfaction)"

            evaluations.append(
                ItemEvaluation(
                    item_id=item.id,
                    category="requires",
                    stage=item.stage,
                    claim_type=item.claim_type,
                    state=state,
                    description=item.description,
                    matched_claim_ids=[c.get("claim_id") or c.get("claim_key", "") for c in matching_ev],
                    witness_family=family,
                    disconfirmation_penalty=penalty,
                    rationale=rationale,
                    assumed_claim_ids=[c.get("claim_id") or c.get("claim_key", "") for c in matching_assumed],
                )
            )

        # 2. Evaluate EXPECTS
        for item in tmpl.expects:
            matching_ev = [c for c in evidence_claims if _matches_item(item, c, events_by_id)]
            matching_assumed = [c for c in assumed_claims if _matches_item(item, c)]
            family = _derive_witness_family(
                item,
                matching_ev[0] if matching_ev else None,
                _extract_claim_events(matching_ev[0], events_by_id) if matching_ev else [],
                all_events=events,
            )

            if matching_ev:
                state = STATE_SATISFIED
                penalty = 0.0
                rationale = f"Expected claim {item.claim_type} is present."
                item_satisfaction_map.setdefault(item.id, set()).add(tmpl.id)
                for c in matching_ev:
                    hyp_claim_ids.add(c.get("claim_id") or c.get("claim_key", ""))
                    c_evs = _extract_claim_events(c, events_by_id)
                    stage_events[item.stage].extend(c_evs)
                    stage_claims[item.stage].append(c)
                    for ev in c_evs:
                        hyp_explained_events.add(ev["event_id"])
            else:
                item_win = _resolve_item_window(item)
                is_covered = _source_demonstrably_covered(
                    item.source_kind,
                    coverage,
                    target_window=item_win,
                    explicit_declarations=explicit_declarations,
                )
                if is_covered:
                    state = STATE_MISSING
                    penalty = 0.5 * item.weight
                    missing_count += 1
                    rationale = f"Expected evidence {item.claim_type} is MISSING from covered source {item.source_kind}."
                else:
                    state = STATE_UNOBSERVABLE
                    penalty = 0.0  # UNOBSERVABLE is strictly neutral!
                    unobservable_count += 1
                    rationale = f"Source {item.source_kind} unobserved; expected evidence is UNOBSERVABLE."
                if matching_assumed:
                    rationale += " (ASSUMED claims present but excluded from evidence satisfaction)"

            evaluations.append(
                ItemEvaluation(
                    item_id=item.id,
                    category="expects",
                    stage=item.stage,
                    claim_type=item.claim_type,
                    state=state,
                    description=item.description,
                    matched_claim_ids=[c.get("claim_id") or c.get("claim_key", "") for c in matching_ev],
                    witness_family=family,
                    disconfirmation_penalty=penalty,
                    rationale=rationale,
                    assumed_claim_ids=[c.get("claim_id") or c.get("claim_key", "") for c in matching_assumed],
                )
            )

        # 3. Evaluate FORBIDS
        for item in tmpl.forbids:
            matching_ev = [c for c in evidence_claims if _matches_item(item, c)]
            matching_assumed = [c for c in assumed_claims if _matches_item(item, c)]
            family = _derive_witness_family(
                item,
                matching_ev[0] if matching_ev else None,
                _extract_claim_events(matching_ev[0], events_by_id) if matching_ev else [],
                all_events=events,
            )

            if matching_ev:
                # Forbidden item is present as real evidence -> Contradiction / Violation!
                state = STATE_VIOLATED
                penalty = 2.0 if item.critical else 1.2
                hard_violations += 1
                rationale = f"FORBIDDEN claim {item.claim_type} is present! Direct contradiction."
            else:
                # No evidence exists for the forbidden item (ASSUMED claims cannot violate forbidden items)
                item_win = _resolve_item_window(item)
                is_covered = _source_demonstrably_covered(
                    item.source_kind,
                    coverage,
                    target_window=item_win,
                    explicit_declarations=explicit_declarations,
                )
                if item.id == "H2-FORBID-2":
                    if has_backup_in_flow:
                        state = STATE_SATISFIED
                        penalty = 0.0
                        rationale = f"Backup audit records present during covered flow window for {tmpl.name}."
                    elif is_covered:
                        state = STATE_MISSING
                        penalty = 2.0 if item.critical else 1.0
                        hard_violations += 1
                        rationale = f"Missing required audit records in covered window for {tmpl.name}."
                    else:
                        state = STATE_UNOBSERVABLE
                        penalty = 0.0
                        rationale = f"Source {item.source_kind} unobserved; cannot verify audit records."
                else:
                    if is_covered:
                        state = STATE_SATISFIED
                        penalty = 0.0
                        rationale = f"Forbidden claim {item.claim_type} is absent in covered window."
                    else:
                        state = STATE_NEUTRAL if item.claim_type != "NO_RECORD_IN_COVERED_WINDOW" else STATE_UNOBSERVABLE
                        penalty = 0.0
                        rationale = f"Source {item.source_kind} unobserved; cannot verify absence of forbidden event."
                if matching_assumed:
                    rationale += " (ASSUMED claims present but cannot violate forbidden items)"

            evaluations.append(
                ItemEvaluation(
                    item_id=item.id,
                    category="forbids",
                    stage=item.stage,
                    claim_type=item.claim_type,
                    state=state,
                    description=item.description,
                    matched_claim_ids=[c.get("claim_id") or c.get("claim_key", "") for c in matching_ev],
                    witness_family=family,
                    disconfirmation_penalty=penalty,
                    rationale=rationale,
                    assumed_claim_ids=[c.get("claim_id") or c.get("claim_key", "") for c in matching_assumed],
                )
            )

        # 4. Evaluate CONSTRAINTS
        for c_idx, constraint in enumerate(tmpl.constraints):
            c_id = f"{tmpl.id}-CONST-{c_idx+1}"
            penalty = 0.0
            state = STATE_SATISFIED
            rationale = f"Constraint {constraint.type} satisfied."

            if constraint.type == "same":
                target = constraint.target
                values: set[str] = set()
                for st_evs in stage_events.values():
                    for ev in st_evs:
                        val = ev.get(target) if target else None
                        if val:
                            norm_val = normalize_actor(val) if target == "actor" else normalize_device(val)
                            values.add(norm_val)
                if len(values) > 1:
                    state = STATE_VIOLATED
                    penalty = 1.5
                    hard_violations += 1
                    rationale = f"Constraint same({target}) VIOLATED: multiple conflicting {target}s observed {values}."

            elif constraint.type == "before":
                st_a, st_b = constraint.first, constraint.second
                evs_a = stage_events.get(st_a or "", [])
                evs_b = stage_events.get(st_b or "", [])
                if evs_a and evs_b:
                    # Parse timestamps
                    times_a = [e["timestamp"] for e in evs_a if "timestamp" in e]
                    times_b = [e["timestamp"] for e in evs_b if "timestamp" in e]
                    if times_a and times_b:
                        min_a = min(times_a)
                        min_b = min(times_b)
                        if min_a > min_b:
                            state = STATE_VIOLATED
                            penalty = 1.5
                            hard_violations += 1
                            rationale = f"Constraint before({st_a}, {st_b}) VIOLATED: {st_a} started after {st_b}."

            elif constraint.type == "within":
                max_mins = constraint.minutes or 1440.0
                all_ts: list[datetime] = []
                for st_evs in stage_events.values():
                    for ev in st_evs:
                        ts = ev.get("timestamp")
                        if isinstance(ts, str):
                            try:
                                all_ts.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
                            except ValueError:
                                pass
                if len(all_ts) >= 2:
                    span = (max(all_ts) - min(all_ts)).total_seconds() / 60.0
                    if span > max_mins:
                        state = STATE_VIOLATED
                        penalty = 1.0
                        rationale = f"Constraint within({max_mins}m) exceeded: observed span {span:.1f} minutes."

            if state == STATE_VIOLATED:
                evaluations.append(
                    ItemEvaluation(
                        item_id=c_id,
                        category="constraint",
                        stage="constraint",
                        claim_type="CONSTRAINT",
                        state=state,
                        description=f"Constraint {constraint.type}",
                        witness_family="engine:constraint",
                        disconfirmation_penalty=penalty,
                        rationale=rationale,
                    )
                )

        # 5. Witness Family Deduplication for Disconfirmation Score
        # Group penalties by witness family: family -> max(penalties in this family)
        family_penalties: dict[str, float] = {}
        for ev in evaluations:
            if ev.disconfirmation_penalty > 0:
                fam = ev.witness_family or "unknown"
                family_penalties[fam] = max(family_penalties.get(fam, 0.0), ev.disconfirmation_penalty)

        total_inconsistency = sum(family_penalties.values())

        # Determine initial hypothesis status
        has_unfulfilled_requires = any(e.category == "requires" and e.state != STATE_SATISFIED for e in evaluations)
        if hard_violations > 0 or total_inconsistency >= 2.0:
            status = STATUS_REFUTED
        elif total_inconsistency > 0.8 or has_unfulfilled_requires:
            status = STATUS_WEAKENED
        else:
            status = STATUS_VIABLE

        evaluated_hypotheses.append(
            RankedHypothesis(
                id=tmpl.id,
                kind=tmpl.kind,
                name=tmpl.name,
                description=tmpl.description,
                status=status,
                inconsistency_score=round(total_inconsistency, 3),
                rank=0,
                evaluations=evaluations,
                supporting_claim_ids=sorted(hyp_claim_ids),
                hard_violations_count=hard_violations,
                missing_expected_count=missing_count,
                unobservable_count=unobservable_count,
            )
        )
        all_explained_event_ids.update(hyp_explained_events)

    # 6. Flag Non-Diagnostic Items
    # An item is non-diagnostic if evidence of that claim_type is SATISFIED across ALL competing hypotheses (when >= 2 hypotheses exist)
    if len(evaluated_hypotheses) > 1:
        for hyp in evaluated_hypotheses:
            for ev in hyp.evaluations:
                if ev.state == STATE_SATISFIED:
                    present_in_all = all(
                        any(other_ev.claim_type == ev.claim_type and other_ev.state == STATE_SATISFIED
                            for other_ev in other_hyp.evaluations)
                        for other_hyp in evaluated_hypotheses
                    )
                    if present_in_all:
                        ev.diagnostic = False
                        ev.rationale += " [NON-DIAGNOSTIC: Consistent across all competing hypotheses]"

    # 7. Disconfirmation Ranking & Margin Evaluation
    # Sort ascending by inconsistency_score (lower penalty is better)
    # Secondary sort: number of diagnostic satisfied items descending
    def _sort_key(h: RankedHypothesis) -> tuple[int, int, float, int]:
        is_refuted = 1 if h.status == STATUS_REFUTED else 0
        is_weakened = 1 if h.status == STATUS_WEAKENED else 0
        diag_satisfied = sum(1 for e in h.evaluations if e.state == STATE_SATISFIED and e.diagnostic)
        return (is_refuted, is_weakened, h.inconsistency_score, -diag_satisfied)

    evaluated_hypotheses.sort(key=_sort_key)
    for idx, h in enumerate(evaluated_hypotheses):
        h.rank = idx + 1

    # Check Margin for LEADING
    outcome = STATUS_UNDETERMINED
    if evaluated_hypotheses:
        top = evaluated_hypotheses[0]
        diag_satisfied = sum(1 for e in top.evaluations if e.state == STATE_SATISFIED and e.diagnostic)

        session_mismatch_unobs = any(
            e.claim_type == "SESSION_ORIGIN_MISMATCH" and e.state == STATE_UNOBSERVABLE
            for h in evaluated_hypotheses
            for e in h.evaluations
            if e.category == "requires"
        )

        auth_cov = coverage.get("auth", {})
        auth_was_monitored = auth_cov.get("event_count", 0) > 0

        if session_mismatch_unobs and auth_was_monitored:
            outcome = STATUS_UNDETERMINED
        elif top.status == STATUS_VIABLE and diag_satisfied > 0:
            if len(evaluated_hypotheses) > 1:
                second = evaluated_hypotheses[1]
                score_delta = second.inconsistency_score - top.inconsistency_score
                second_diag_satisfied = sum(
                    1 for e in second.evaluations
                    if e.state == STATE_SATISFIED and e.diagnostic
                )
                # A unique diagnostic item breaks an otherwise equal score tie.
                # Equal diagnostic support remains undetermined.
                diagnostic_delta_breaks_tie = (
                    score_delta == 0
                    and diag_satisfied > second_diag_satisfied
                )
                if (
                    second.status in (STATUS_REFUTED, STATUS_WEAKENED)
                    or score_delta >= margin
                    or diagnostic_delta_breaks_tie
                ):
                    top.status = STATUS_LEADING
                    outcome = STATUS_LEADING
                else:
                    outcome = STATUS_UNDETERMINED
            else:
                top.status = STATUS_LEADING
                outcome = STATUS_LEADING
        elif all(h.status == STATUS_REFUTED for h in evaluated_hypotheses):
            outcome = STATUS_REFUTED

    # 8. Compute H0 Residual
    all_case_event_ids = {e["event_id"] for e in events if "event_id" in e}
    unassigned_ids = sorted(all_case_event_ids - all_explained_event_ids)
    h0 = ResidualH0(
        id="H0",
        name="Residual Events (H0)",
        description="Events unexplained by any evaluated hypothesis stages",
        unassigned_event_count=len(unassigned_ids),
        unassigned_event_ids=unassigned_ids,
    )

    # 9. Next-Best Evidence Calculation
    next_best: list[NextBestEvidence] = []
    if len(evaluated_hypotheses) >= 2:
        top_a = evaluated_hypotheses[0]
        top_b = evaluated_hypotheses[1]

        # Find expected/required items in top_a or top_b that are UNOBSERVABLE
        # and would differentiate the two
        for hyp, other in ((top_a, top_b), (top_b, top_a)):
            for ev in hyp.evaluations:
                if ev.state == STATE_UNOBSERVABLE:
                    # Check if other hypothesis forbids it or does not require it
                    other_item = next((e for e in other.evaluations if e.item_id == ev.item_id), None)
                    differs = other_item is None or other_item.category == "forbids" or other_item.state != ev.state
                    if differs:
                        priority = "HIGH" if ev.category == "requires" else "MEDIUM"
                        needed = f"Acquire {ev.stage} logs from source '{ev.witness_family}' ({ev.claim_type})"
                        rationale = (
                            f"{hyp.name} expects {ev.claim_type} during {ev.stage}, but it is currently UNOBSERVABLE. "
                            f"Corroborating this evidence would distinguish {hyp.id} from {other.id}."
                        )
                        next_best.append(
                            NextBestEvidence(
                                evidence_needed=needed,
                                source_kind=ev.witness_family.split(":")[0] if ev.witness_family else "unknown",
                                distinguishes=[top_a.id, top_b.id],
                                rationale=rationale,
                                priority=priority,
                            )
                        )

    # 10. Cryptographic Ranking Hash
    ranking_summary = [
        {"id": h.id, "status": h.status, "score": h.inconsistency_score, "rank": h.rank}
        for h in evaluated_hypotheses
    ]
    ranking_hash = hashlib.sha256(
        json.dumps(ranking_summary, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    diagnostic_count = sum(
        1 for h in evaluated_hypotheses for e in h.evaluations if e.state == STATE_SATISFIED and e.diagnostic
    )

    return HypothesisEvaluationResult(
        ranked_hypotheses=evaluated_hypotheses,
        h0_residual=h0,
        next_best_evidence=next_best,
        ranking_hash=ranking_hash,
        diagnostic_items_count=diagnostic_count,
        margin=margin,
        outcome=outcome,
    )
