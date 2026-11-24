"""Role 3: immutable investigation report built from one completed analysis run.

Inputs, and nothing else:
- the AnalysisRun row (write-once) and its authoritative RunSnapshot (write-once)
- the Claim and ClaimEdge rows stored with that run
- the Evidence rows named in the run's manifest, and the case they belong to

Nothing is recomputed: no correlation, claim generation or hypothesis evaluation runs here.
Values that teammate-owned modules do not produce yet are printed as explicitly unavailable
(see UNAVAILABLE_FIELDS), never estimated.

Flow: load_report_inputs() validates and loads -> build_report_content() produces canonical
JSON-safe content -> content_hash() -> render_report_pdf() -> the router persists a CaseReport.
"""
from __future__ import annotations

import hashlib
import io
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from app.db.models import (
    EVIDENCE_ACTIVE,
    AnalysisRun,
    Case,
    Claim,
    ClaimEdge,
    CustodyEntry,
    Evidence,
    RunSnapshot,
)

REPORT_GENERATOR_VERSION = "pramana-run-report@1.0.0"
NOT_RECORDED = "Not recorded"
REVIEW_STATUS_TEXT = "Pending review"

SECTION_TITLES = (
    "1. Cover and case details",
    "2. Executive summary",
    "3. Evidence inventory",
    "4. Methodology",
    "5. Correlation findings",
    "6. Hypotheses",
    "7. Reconstructed timeline",
    "8. Limitations",
    "9. Reviewer decision",
    "10. Integrity and reproducibility",
)

# Fields the architecture document requires but no module produces yet. Printed verbatim.
UNAVAILABLE_FIELDS: dict[str, str] = {
    "correlation_registry_version": (
        "Unavailable: the correlation parameter registry exists (intelligence/correlation/registry_v1.json), "
        "but its configuration and results are not recorded with this run (correlation engine, Shambhavi)."
    ),
    "scoring_thresholds": (
        "Unavailable: correlation scoring thresholds are defined in the registry, but the values applied are "
        "not recorded with this run (correlation engine, Shambhavi)."
    ),
    "relationship_score": "Unavailable: per-relationship scores and contributing parameters are not stored with the run (correlation engine, Shambhavi).",
    "relationship_type": "Unavailable: primary/secondary relationship type is not stored with the run (correlation engine, Shambhavi).",
    "clock_uncertainty": "Unavailable: per-event clock uncertainty is not recorded; only the time-zone assumption is stored.",
    "source_coverage": "Unavailable: source coverage is a stub table with no fields yet (Niharika, T7/T8).",
    "inaccessible_sources": "Unavailable: inaccessible-source and encrypted-payload limits are not recorded at acquisition (evidence acquisition/provenance, Anupriya).",
    "reviewer_identity": "Unavailable: authentication is not implemented, so reviewer identity cannot be verified.",
}


class ReportInputError(Exception):
    """A report cannot be generated for this case/run. status_code maps to the HTTP response."""

    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass
class ReportInputs:
    case: Case
    run: AnalysisRun
    snapshot: RunSnapshot
    claims: list[Claim]
    edges: list[ClaimEdge]
    evidence: list[Evidence]  # manifest order
    custody_heads: dict[str, str | None]  # evidence_id -> latest custody entry_hash


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_hash(content: dict[str, Any]) -> str:
    return sha256_hex(_canonical(content))


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


# --------------------------------------------------------------------------------------------- inputs

def load_report_inputs(db: Session, case_id: str, run_id: str) -> ReportInputs:
    """Load and validate everything the report may use. Raises ReportInputError."""
    case = db.get(Case, case_id)
    if case is None:
        raise ReportInputError(404, f"Case '{case_id}' not found")

    run = db.get(AnalysisRun, run_id)
    # A run of another case is reported exactly like a missing one, so IDs do not leak across cases.
    if run is None or run.case_id != case_id:
        raise ReportInputError(404, f"Run '{run_id}' not found in case '{case_id}'")

    snapshot = db.get(RunSnapshot, run_id)
    if snapshot is None or snapshot.case_id != case_id or not isinstance(snapshot.snapshot, dict):
        raise ReportInputError(
            409,
            f"Run '{run_id}' has no authoritative database snapshot; reports are only generated from "
            "authoritative run snapshots",
        )

    manifest = run.manifest.get("evidence", []) if isinstance(run.manifest, dict) else []
    reasons: list[str] = []
    evidence: list[Evidence] = []
    for item in manifest:
        ev_id = item.get("evidence_id")
        ev = db.get(Evidence, ev_id)
        if ev is None:
            reasons.append(f"evidence '{ev_id}' no longer exists")
        elif ev.case_id != case_id:
            reasons.append(f"evidence '{ev_id}' does not belong to case '{case_id}'")
        elif ev.status != EVIDENCE_ACTIVE:
            reasons.append(f"evidence '{ev_id}' status is {ev.status} (verify_state: {ev.verify_state})")
        elif ev.sha256 != item.get("sha256"):
            reasons.append(f"evidence '{ev_id}' SHA-256 differs from the run manifest")
        else:
            evidence.append(ev)
    if not manifest:
        reasons.append("the run manifest lists no evidence")
    if reasons:
        raise ReportInputError(409, f"Run '{run_id}' is invalidated: " + "; ".join(reasons))

    claims = (
        db.query(Claim)
        .filter(Claim.run_id == run_id, Claim.case_id == case_id)
        .order_by(Claim.claim_id.asc())
        .all()
    )
    edges = (
        db.query(ClaimEdge)
        .filter(ClaimEdge.run_id == run_id)
        .order_by(ClaimEdge.claim_id.asc(), ClaimEdge.ref_kind.asc(), ClaimEdge.ref_id.asc(), ClaimEdge.role.asc())
        .all()
    )

    custody_heads: dict[str, str | None] = {}
    for ev in evidence:
        head = (
            db.query(CustodyEntry)
            .filter(CustodyEntry.evidence_id == ev.evidence_id)
            .order_by(CustodyEntry.id.desc())
            .first()
        )
        custody_heads[ev.evidence_id] = head.entry_hash if head is not None else None

    return ReportInputs(case, run, snapshot, claims, edges, evidence, custody_heads)


# -------------------------------------------------------------------------------------------- content

def _event_index(events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {e.get("event_id"): e for e in events if isinstance(e, dict) and e.get("event_id")}


def build_report_content(inputs: ReportInputs) -> dict[str, Any]:
    """Canonical, JSON-safe report content. Deterministic for a given run (no report_id or clock)."""
    case, run, snap = inputs.case, inputs.run, inputs.snapshot.snapshot
    events: list[dict[str, Any]] = [e for e in (snap.get("events") or []) if isinstance(e, dict)]
    events_by_id = _event_index(events)
    ranked: list[dict[str, Any]] = [h for h in (snap.get("ranked_hypotheses") or []) if isinstance(h, dict)]
    reconstruction = snap.get("reconstruction") if isinstance(snap.get("reconstruction"), dict) else None
    h0 = snap.get("h0_residual") if isinstance(snap.get("h0_residual"), dict) else {}
    next_best = [n for n in (snap.get("next_best_evidence") or []) if isinstance(n, dict)]
    manifest_sha = {m.get("evidence_id"): m.get("sha256") for m in run.manifest.get("evidence", [])}

    edges_by_claim: dict[str, list[ClaimEdge]] = {}
    for edge in inputs.edges:
        edges_by_claim.setdefault(edge.claim_id, []).append(edge)

    # 1. Cover
    cover = {
        "case_id": case.case_id,
        "case_title": case.name,
        "investigator": case.owner or NOT_RECORDED,
        "investigator_identity": "self-declared",
        "scope": case.scope or NOT_RECORDED,
        "description": case.description or NOT_RECORDED,
        "run_id": run.run_id,
        "parent_run_id": run.parent_run_id,
        "run_created_at": _iso(run.created_at),
        "engine_version": run.engine_version,
        "generator_version": REPORT_GENERATOR_VERSION,
        "review_status": REVIEW_STATUS_TEXT,
    }

    # 2. Executive summary (fixed wording from stored values; no model output)
    claim_status = Counter(c.status for c in inputs.claims)
    leading = ranked[0] if ranked else None
    unobservable = sum(
        1 for h in ranked for item in (h.get("evaluations") or []) if isinstance(item, dict) and item.get("state") == "UNOBSERVABLE"
    )
    summary_lines = [
        f"Analysis run {run.run_id} evaluated {len(ranked)} competing hypotheses over {len(events)} events "
        f"from {len(inputs.evidence)} evidence items, producing {len(inputs.claims)} claims.",
    ]
    if leading:
        summary_lines.append(
            f"Highest-ranked hypothesis: {leading.get('name', leading.get('id'))} ({leading.get('id')}), "
            f"status {leading.get('status')}, inconsistency score {leading.get('inconsistency_score')}."
        )
    else:
        summary_lines.append("The run ranked no hypotheses.")
    summary_lines.append(
        f"{int(h0.get('unassigned_event_count') or 0)} events are not explained by any evaluated hypothesis; "
        f"{unobservable} expected or required items could not be observed in the available sources."
    )
    summary_lines.append(
        "This summary describes stored machine analysis only. It is not a reviewer decision; "
        f"review status: {REVIEW_STATUS_TEXT}."
    )
    executive_summary = {
        "outcome": snap.get("outcome") or NOT_RECORDED,
        "lines": summary_lines,
        "hypothesis_status": [
            {"id": h.get("id"), "name": h.get("name"), "status": h.get("status"), "rank": h.get("rank")} for h in ranked
        ],
        "claim_status_counts": dict(sorted(claim_status.items())),
    }

    # 3. Evidence inventory (manifest evidence only)
    inventory = []
    for ev in inputs.evidence:
        inventory.append({
            "evidence_id": ev.evidence_id,
            "source_type": ev.source_type or NOT_RECORDED,
            "original_name": ev.source_identifier or ev.filename,
            "filename": ev.filename,
            "acquisition_method": ev.acquisition_method or NOT_RECORDED,
            "acquired_by": ev.acquired_by or NOT_RECORDED,
            "acquired_at": _iso(ev.intake_time),
            "size_bytes": ev.size_bytes,
            "sha256": ev.sha256,
            "manifest_sha256_match": manifest_sha.get(ev.evidence_id) == ev.sha256,
            "parser": f"{ev.parser_name}@{ev.parser_version}" if ev.parser_name else NOT_RECORDED,
            "parse_status": ev.parse_status or NOT_RECORDED,
            "parser_warnings": list(ev.parser_warnings or []),
            "covered_time_range": ev.covered_time_range or NOT_RECORDED,
        })

    # 4. Methodology
    families = Counter(e.get("family") or e.get("source") or "unknown" for e in events)
    tz_assumptions = Counter(e.get("tz_assumption") or "not recorded" for e in events)
    rules = sorted({f"{c.rule_id}@{c.rule_version}" for c in inputs.claims})
    templates = [t for t in (snap.get("templates") or []) if isinstance(t, dict)]
    methodology = {
        "data_sources": dict(sorted(families.items())),
        "parser_versions": run.parser_versions,
        "time_normalisation": {
            "case_timezone_assumption": (snap.get("assumptions") or {}).get("case_timezone", NOT_RECORDED),
            "event_tz_assumptions": dict(sorted(tz_assumptions.items())),
        },
        "assumptions": snap.get("assumptions") or {},
        "claim_rules": rules,
        "hypothesis_templates": [{"id": t.get("id"), "name": t.get("name")} for t in templates],
        "template_hash": inputs.snapshot.template_hash,
        "engine_version": run.engine_version,
        "analysis_stages": [
            "Evidence intake: SHA-256 hashing and chain of custody",
            "Deterministic parsing into normalised events",
            "Rule-based correlation into claims (T5/T6), stored with the run",
            "Hypothesis evaluation and ranking (T7), stored in the run snapshot",
            "Narrative reconstruction of the leading hypothesis (T8), stored in the run snapshot",
        ],
        "correlation_registry_version": UNAVAILABLE_FIELDS["correlation_registry_version"],
        "scoring_thresholds": UNAVAILABLE_FIELDS["scoring_thresholds"],
    }

    # 5. Correlation findings (stored claims and edges only)
    findings = []
    for c in inputs.claims:
        refs = edges_by_claim.get(c.claim_id, [])

        def _ref(edge: ClaimEdge) -> dict[str, Any]:
            ev = events_by_id.get(edge.ref_id) if edge.ref_kind == "event" else None
            return {
                "ref_kind": edge.ref_kind,
                "ref_id": edge.ref_id,
                "reason_code": edge.reason_code,
                "family": edge.family,
                "weight": edge.weight,
                "evidence_id": ev.get("evidence_id") if ev else None,
                "artifact_ref": ev.get("artifact_ref") if ev else None,
            }

        findings.append({
            "claim_id": c.claim_id,
            "type": c.type,
            "status": c.status,
            "grade": c.grade,
            "rule": f"{c.rule_id}@{c.rule_version}",
            "params": c.params,
            "supports": [_ref(e) for e in refs if e.role == "SUPPORTS"],
            "counter_signals": [_ref(e) for e in refs if e.role == "CONTRADICTS"],
        })
    correlation = {
        "claims": findings,
        "relationship_score": UNAVAILABLE_FIELDS["relationship_score"],
        "relationship_type": UNAVAILABLE_FIELDS["relationship_type"],
        "note": "Claim grade is an evidence-strength category (A strongest), not a probability. "
        "Edge weight is the stored edge weight, not a relationship score.",
    }

    # 6. Hypotheses
    hypotheses = []
    for h in ranked:
        items = []
        for item in h.get("evaluations") or []:
            if not isinstance(item, dict):
                continue
            items.append({
                "item_id": item.get("item_id"),
                "category": item.get("category"),
                "stage": item.get("stage"),
                "claim_type": item.get("claim_type"),
                "state": item.get("state"),
                "rationale": item.get("rationale"),
                "matched_claim_ids": list(item.get("matched_claim_ids") or []),
            })
        hypotheses.append({
            "id": h.get("id"),
            "name": h.get("name"),
            "description": h.get("description"),
            "rank": h.get("rank"),
            "status": h.get("status"),
            "inconsistency_score": h.get("inconsistency_score"),
            # States from intelligence/hyp/engine.py: SATISFIED, VIOLATED, MISSING, UNOBSERVABLE, NEUTRAL.
            "supporting_items": [i for i in items if i["state"] == "SATISFIED"],
            "contradicting_items": [i for i in items if i["state"] == "VIOLATED"],
            "open_items": [i for i in items if i["state"] in ("MISSING", "UNOBSERVABLE")],
            "all_items": items,
        })
    hypotheses_section = {
        "ranked": hypotheses,
        "unresolved_questions": [
            {"evidence_needed": n.get("evidence_needed"), "distinguishes": n.get("distinguishes"),
             "priority": n.get("priority"), "rationale": n.get("rationale")}
            for n in next_best
        ],
        "qualification": "Hypothesis status is a category derived from contradicting evidence, not a probability.",
    }

    # 7. Reconstructed timeline
    stages = []
    if reconstruction:
        for st in reconstruction.get("stages") or []:
            if not isinstance(st, dict):
                continue
            stage_events = sorted(
                (e for e in (st.get("raw_events") or []) if isinstance(e, dict)),
                key=lambda e: (str(e.get("timestamp")), str(e.get("event_id"))),
            )
            stages.append({
                "stage_name": st.get("stage_name"),
                "status": st.get("status"),
                "time_window": st.get("time_window"),
                "relationship_to_previous": st.get("relationship_to_previous"),
                "claim_ids": [c.get("claim_id") for c in (st.get("claims") or []) if isinstance(c, dict)],
                "events": [
                    {"timestamp": e.get("timestamp"), "event_id": e.get("event_id"), "action": e.get("action"),
                     "actor": e.get("actor"), "evidence_id": e.get("evidence_id"),
                     "artifact_ref": e.get("artifact_ref"), "tz_assumption": e.get("tz_assumption") or NOT_RECORDED}
                    for e in stage_events
                ],
            })
    timeline = {
        "hypothesis": (
            f"{reconstruction.get('hypothesis_name')} ({reconstruction.get('hypothesis_id')}), status {reconstruction.get('status')}"
            if reconstruction else "No reconstruction stored with this run."
        ),
        "narrative_summary": (reconstruction or {}).get("narrative_summary") or NOT_RECORDED,
        "stages": stages,
        "gaps": [s["stage_name"] for s in stages if s["status"] != "SUPPORTED"],
        "background_event_count": (reconstruction or {}).get("background_activity_count", 0),
        "clock_uncertainty": UNAVAILABLE_FIELDS["clock_uncertainty"],
    }

    # 8. Limitations
    unobserved = sorted({
        f"{item.get('claim_type')} ({item.get('state')}): {item.get('rationale')}"
        for h in ranked for item in (h.get("evaluations") or [])
        if isinstance(item, dict) and item.get("state") in ("UNOBSERVABLE", "MISSING")
    })
    parser_warnings = [
        f"{ev['evidence_id']}: {w}" for ev in inventory for w in ev["parser_warnings"]
    ]
    not_parsed = [ev["evidence_id"] for ev in inventory if ev["parse_status"] not in (NOT_RECORDED, "PARSED", "parsed", "SUCCESS", "success")]
    implicit_tz = sum(n for tz, n in tz_assumptions.items() if tz != "explicit_offset")
    limitations = {
        "unobservable_or_missing_items": unobserved,
        "unexplained_events": list(h0.get("unassigned_event_ids") or []),
        "parser_warnings": parser_warnings,
        "evidence_with_non_success_parse_status": not_parsed,
        "events_without_explicit_offset": implicit_tz,
        "source_coverage": UNAVAILABLE_FIELDS["source_coverage"],
        "inaccessible_sources": UNAVAILABLE_FIELDS["inaccessible_sources"],
        "statements": [
            "Only evidence listed in the run manifest is considered; later uploads are not part of this report.",
            "Claim rules and hypothesis templates are fixed at their recorded versions; thresholds are provisional.",
            "This report is investigator support material aligned with BSA Section 63 certificate fields. "
            "It is not a legal certificate.",
        ],
    }

    # 9. Reviewer decision (kept separate from machine findings)
    reviewer = {
        "status": REVIEW_STATUS_TEXT,
        "explanation": "Reviewer decisions (approve / reject / inconclusive) are recorded as separate append-only "
        "records linked to this report_id. This document is immutable and is never edited after generation.",
        "reviewer_identity": UNAVAILABLE_FIELDS["reviewer_identity"],
    }

    # 10. Integrity and reproducibility
    integrity = {
        "run_id": run.run_id,
        "manifest_evidence": [{"evidence_id": m.get("evidence_id"), "sha256": m.get("sha256")} for m in run.manifest.get("evidence", [])],
        "assumptions_hash": run.assumptions_hash,
        "ranking_hash": run.ranking_hash or NOT_RECORDED,
        "template_hash": inputs.snapshot.template_hash,
        "snapshot_created_at": _iso(inputs.snapshot.created_at),
        "snapshot_source": "authoritative database snapshot (run_snapshots)",
        "custody_head_hashes": {k: (v or NOT_RECORDED) for k, v in sorted(inputs.custody_heads.items())},
        "generator_version": REPORT_GENERATOR_VERSION,
        "pdf_hash_note": "The SHA-256 of this PDF file cannot be printed inside it; it is stored with the report "
        "record and returned by the API, and is re-verified before every download.",
    }

    return {
        "cover": cover,
        "executive_summary": executive_summary,
        "evidence_inventory": inventory,
        "methodology": methodology,
        "correlation_findings": correlation,
        "hypotheses": hypotheses_section,
        "timeline": timeline,
        "limitations": limitations,
        "reviewer_decision": reviewer,
        "integrity": integrity,
    }


# ----------------------------------------------------------------------------------------------- PDF

_INK = colors.HexColor("#1A202C")
_MUTED = colors.HexColor("#4A5568")
_RULE = colors.HexColor("#CBD5E0")
_HEAD_BG = colors.HexColor("#EDF2F7")
_UNAVAILABLE_BG = colors.HexColor("#FFF5F5")


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    body = ParagraphStyle("Body", parent=base["Normal"], fontName="Helvetica", fontSize=8.5, leading=11, textColor=_INK)
    return {
        "title": ParagraphStyle("Title", parent=base["Title"], fontName="Helvetica-Bold", fontSize=17, leading=21,
                                textColor=colors.HexColor("#1A365D"), spaceAfter=4),
        "subtitle": ParagraphStyle("Sub", parent=body, fontSize=9.5, leading=13, textColor=_MUTED, spaceAfter=8),
        "h1": ParagraphStyle("H1", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=12.5, leading=16,
                             textColor=colors.HexColor("#2B6CB0"), spaceBefore=12, spaceAfter=6),
        "h2": ParagraphStyle("H2", parent=body, fontName="Helvetica-Bold", fontSize=9.5, leading=13, spaceBefore=6, spaceAfter=3),
        "body": body,
        "small": ParagraphStyle("Small", parent=body, fontSize=7.5, leading=9.5, textColor=_MUTED, spaceBefore=3, spaceAfter=2),
        # Hashes and IDs have no spaces; CJK wrapping lets them break anywhere instead of overflowing.
        "mono": ParagraphStyle("Mono", parent=body, fontName="Courier", fontSize=7, leading=9, wordWrap="CJK"),
        "unavailable": ParagraphStyle("Unavail", parent=body, fontSize=8, leading=10.5, textColor=colors.HexColor("#9B2C2C"),
                                      backColor=_UNAVAILABLE_BG, borderPadding=3, spaceBefore=2, spaceAfter=4),
    }


def _p(text: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape("" if text is None else str(text)), style)


def _table(rows: list[list[Any]], widths: list[float]) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _HEAD_BG),
        ("GRID", (0, 0), (-1, -1), 0.4, _RULE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def _kv(rows: list[tuple[str, Any]], s: dict[str, ParagraphStyle], mono_keys: set[str] = frozenset(), width: float = 180 * mm) -> Table:
    data = [[_p("Field", s["h2"]), _p("Value", s["h2"])]]
    for key, value in rows:
        style = s["mono"] if key in mono_keys else s["body"]
        if isinstance(value, (dict, list)):
            value = json.dumps(value, sort_keys=True, ensure_ascii=False)
            style = s["mono"]
        data.append([_p(key, s["body"]), _p(value, style)])
    return _table(data, [48 * mm, width - 48 * mm])


def render_report_pdf(content: dict[str, Any], meta: dict[str, Any]) -> bytes:
    """Render the 10 sections. `meta` carries report_id, report_version, generated_at and content_hash."""
    s = _styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
        title=f"PRAMANA report {meta['report_id']}", author="PRAMANA", subject=f"Run {content['cover']['run_id']}",
        invariant=1,
    )
    width = A4[0] - 30 * mm
    story: list[Any] = []

    def section(i: int) -> None:
        story.append(_p(SECTION_TITLES[i], s["h1"]))

    def unavailable(text: str) -> None:
        story.append(_p(text, s["unavailable"]))

    cover = content["cover"]
    story.append(_p("PRAMANA Investigation Report", s["title"]))
    story.append(_p(
        f"Report {meta['report_id']} · version {meta['report_version']} · generated {meta['generated_at']} · "
        f"review status: {cover['review_status']}", s["subtitle"]))

    # 1
    section(0)
    story.append(_kv([
        ("Case ID", cover["case_id"]), ("Case title", cover["case_title"]),
        ("Investigator", f"{cover['investigator']} ({cover['investigator_identity']})"),
        ("Scope", cover["scope"]), ("Description", cover["description"]),
        ("Report ID", meta["report_id"]), ("Report version", meta["report_version"]),
        ("Generated at", meta["generated_at"]), ("Generated by", meta.get("generated_by") or NOT_RECORDED),
        ("Analysis run", cover["run_id"]), ("Parent run", cover["parent_run_id"] or "None"),
        ("Run created at", cover["run_created_at"]), ("Engine version", cover["engine_version"]),
        ("Report generator", cover["generator_version"]), ("Review status", cover["review_status"]),
    ], s, {"Report ID", "Analysis run", "Parent run"}, width))

    # 2
    section(1)
    summary = content["executive_summary"]
    for line in summary["lines"]:
        story.append(_p(line, s["body"]))
        story.append(Spacer(1, 2))
    rows = [[_p("Rank", s["h2"]), _p("Hypothesis", s["h2"]), _p("Status", s["h2"])]]
    rows += [[_p(h["rank"], s["body"]), _p(f"{h['name']} ({h['id']})", s["body"]), _p(h["status"], s["body"])]
             for h in summary["hypothesis_status"]]
    if len(rows) > 1:
        story.append(_table(rows, [15 * mm, width - 55 * mm, 40 * mm]))
    story.append(_p(f"Outcome: {summary['outcome']} · Claims by status: "
                    + (", ".join(f"{k} {v}" for k, v in summary["claim_status_counts"].items()) or "none"), s["small"]))

    # 3
    section(2)
    rows = [[_p(h, s["h2"]) for h in ("Evidence", "Source / acquisition", "Size", "SHA-256 (manifest match)", "Parser / warnings")]]
    for ev in content["evidence_inventory"]:
        rows.append([
            _p(ev["evidence_id"], s["mono"]),
            _p(f"{ev['original_name']} · type {ev['source_type']} · {ev['acquisition_method']} by {ev['acquired_by']} "
               f"at {ev['acquired_at']}", s["body"]),
            _p(f"{ev['size_bytes']} B", s["body"]),
            _p(f"{ev['sha256']} ({'match' if ev['manifest_sha256_match'] else 'MISMATCH'})", s["mono"]),
            _p(f"{ev['parser']} · {ev['parse_status']}"
               + (f" · warnings: {'; '.join(map(str, ev['parser_warnings']))}" if ev["parser_warnings"] else " · no warnings"),
               s["body"]),
        ])
    story.append(_table(rows, [20 * mm, 52 * mm, 16 * mm, 50 * mm, width - 138 * mm]))

    # 4
    section(3)
    m = content["methodology"]
    story.append(_kv([
        ("Data sources (events per family)", m["data_sources"]), ("Parser versions", m["parser_versions"]),
        ("Time normalisation", m["time_normalisation"]), ("Assumptions", m["assumptions"]),
        ("Claim rules", ", ".join(m["claim_rules"]) or "none"),
        ("Hypothesis templates", ", ".join(f"{t['id']} {t['name']}" for t in m["hypothesis_templates"]) or "none"),
        ("Template hash", m["template_hash"]), ("Engine version", m["engine_version"]),
    ], s, {"Template hash"}, width))
    story.append(_p("Analysis stages: " + " → ".join(m["analysis_stages"]), s["small"]))
    unavailable(m["correlation_registry_version"])
    unavailable(m["scoring_thresholds"])

    # 5
    section(4)
    corr = content["correlation_findings"]
    unavailable(corr["relationship_score"])
    unavailable(corr["relationship_type"])
    story.append(_p(corr["note"], s["small"]))
    if not corr["claims"]:
        story.append(_p("No claims were stored with this run.", s["body"]))
    for c in corr["claims"]:
        def refs(items: list[dict[str, Any]]) -> str:
            if not items:
                return "none"
            return "; ".join(
                f"{r['ref_kind']} {r['ref_id']} [{r['reason_code']}, family {r['family']}, weight {r['weight']}"
                + (f", {r['evidence_id']} {r['artifact_ref']}" if r.get("evidence_id") else "") + "]"
                for r in items
            )
        story.append(KeepTogether([
            _p(f"{c['type']} · {c['status']} · grade {c['grade']} · {c['rule']}", s["h2"]),
            _p(f"Claim {c['claim_id']}", s["mono"]),
            _p("Parameters: " + json.dumps(c["params"], sort_keys=True, ensure_ascii=False), s["mono"]),
            _p("Supported by: " + refs(c["supports"]), s["body"]),
            _p("Counter-signals: " + refs(c["counter_signals"]), s["body"]),
        ]))

    # 6
    section(5)
    hyp = content["hypotheses"]
    story.append(_p(hyp["qualification"], s["small"]))
    for h in hyp["ranked"]:
        story.append(_p(f"#{h['rank']} {h['name']} ({h['id']}) · {h['status']} · inconsistency score {h['inconsistency_score']}", s["h2"]))
        story.append(_p(h["description"], s["body"]))
        rows = [[_p(x, s["h2"]) for x in ("Item", "Stage / claim type", "State", "Rationale")]]
        rows += [[_p(i["item_id"], s["mono"]), _p(f"{i['stage']} · {i['claim_type']} ({i['category']})", s["body"]),
                  _p(i["state"], s["body"]), _p(i["rationale"], s["body"])] for i in h["all_items"]]
        if len(rows) > 1:
            story.append(_table(rows, [22 * mm, 48 * mm, 29 * mm, width - 99 * mm]))
    story.append(_p("Unresolved questions (next best evidence)", s["h2"]))
    if hyp["unresolved_questions"]:
        for q in hyp["unresolved_questions"]:
            story.append(_p(f"[{q['priority']}] {q['evidence_needed']} (distinguishes {', '.join(q['distinguishes'] or [])}). "
                            f"{q['rationale']}", s["body"]))
    else:
        story.append(_p("None recorded.", s["body"]))

    # 7
    section(6)
    tl = content["timeline"]
    story.append(_p(f"Reconstruction: {tl['hypothesis']}", s["body"]))
    story.append(_p(f"Summary: {tl['narrative_summary']}", s["body"]))
    story.append(_p(f"Gaps: {', '.join(tl['gaps']) if tl['gaps'] else 'none'} · background events: {tl['background_event_count']}", s["small"]))
    unavailable(tl["clock_uncertainty"])
    for st in tl["stages"]:
        window = st["time_window"] or {}
        story.append(_p(f"Stage {st['stage_name']} · {st['status']} · {window.get('lo', '?')} → {window.get('hi', '?')} · "
                        f"{st['relationship_to_previous']}", s["h2"]))
        rows = [[_p(x, s["h2"]) for x in ("Timestamp", "Event", "Source artifact", "Time zone")]]
        rows += [[_p(e["timestamp"], s["mono"]), _p(f"{e['action']} by {e['actor']}", s["body"]),
                  _p(f"{e['evidence_id']} {e['artifact_ref']}", s["mono"]), _p(e["tz_assumption"], s["body"])]
                 for e in st["events"]]
        if len(rows) > 1:
            story.append(_table(rows, [36 * mm, 40 * mm, width - 106 * mm, 30 * mm]))
        else:
            story.append(_p("No events assigned to this stage.", s["small"]))

    # 8
    section(7)
    lim = content["limitations"]
    for title, items in (
        ("Unobservable or missing hypothesis items", lim["unobservable_or_missing_items"]),
        ("Events not explained by any hypothesis", lim["unexplained_events"]),
        ("Parser warnings", lim["parser_warnings"]),
        ("Evidence whose parse status is not a success", lim["evidence_with_non_success_parse_status"]),
    ):
        story.append(_p(title, s["h2"]))
        story.append(_p("; ".join(map(str, items)) if items else "None recorded.", s["mono"] if title.startswith("Events") else s["body"]))
    story.append(_p(f"Events without an explicit time-zone offset: {lim['events_without_explicit_offset']}", s["body"]))
    unavailable(lim["source_coverage"])
    unavailable(lim["inaccessible_sources"])
    for line in lim["statements"]:
        story.append(_p(line, s["small"]))

    # 9
    section(8)
    rev = content["reviewer_decision"]
    story.append(_p(f"Status: {rev['status']}", s["h2"]))
    story.append(_p(rev["explanation"], s["body"]))
    unavailable(rev["reviewer_identity"])

    # 10
    section(9)
    integ = content["integrity"]
    story.append(_kv([
        ("Report content hash (SHA-256)", meta["content_hash"]), ("Analysis run", integ["run_id"]),
        ("Assumptions hash", integ["assumptions_hash"]), ("Ranking hash", integ["ranking_hash"]),
        ("Template hash", integ["template_hash"]), ("Snapshot", f"{integ['snapshot_source']}, created {integ['snapshot_created_at']}"),
        ("Report generator", integ["generator_version"]),
    ], s, {"Report content hash (SHA-256)", "Analysis run", "Assumptions hash", "Ranking hash", "Template hash"}, width))
    rows = [[_p(x, s["h2"]) for x in ("Evidence", "Manifest SHA-256", "Latest custody entry hash")]]
    rows += [[_p(m_["evidence_id"], s["mono"]), _p(m_["sha256"], s["mono"]),
              _p(integ["custody_head_hashes"].get(m_["evidence_id"], NOT_RECORDED), s["mono"])]
             for m_ in integ["manifest_evidence"]]
    story.append(_table(rows, [22 * mm, (width - 22 * mm) / 2, (width - 22 * mm) / 2]))
    story.append(_p(integ["pdf_hash_note"], s["small"]))

    def on_page(canvas, document) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(_MUTED)
        canvas.drawString(15 * mm, 9 * mm, f"PRAMANA · {meta['report_id']} · run {content['cover']['run_id']} · {REVIEW_STATUS_TEXT}")
        canvas.drawRightString(A4[0] - 15 * mm, 9 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buffer.getvalue()
