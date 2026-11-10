"""Run all PRAMANA synthetic benchmark scenarios and write evaluated results."""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "evidence-engine", ROOT / "backend"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from bench.baselines import time_window_only, time_window_shared_identifier
from bench.gen.simulator import SCENARIO_DIR, generate
from bench.metrics import aggregate_metrics, scenario_metrics


DEFAULT_RESULTS_DIR = ROOT / "bench" / "results"
DEFAULT_REPORT = ROOT / "bench" / "REPORT.md"
LINK_CLAIM_TYPES = {"SAME_OBJECT_FLOW"}


def _stable_output(value: Any) -> Any:
    """Remove run-instance metadata while preserving reproducible analysis content."""
    if isinstance(value, dict):
        return {
            key: _stable_output(item)
            for key, item in value.items()
            if key not in {"run_id", "created_at"}
        }
    if isinstance(value, list):
        return [_stable_output(item) for item in value]
    return value


def _event_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc).replace(tzinfo=None)
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def _parse_scenario_events(
    scenario_id: str,
    evidence_root: Path,
    evidence_files: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    from parsers import parse_evidence

    events: list[dict[str, Any]] = []
    for index, evidence in enumerate(evidence_files, 1):
        evidence_path = evidence_root / evidence["path"]
        evidence_id = f"{scenario_id}-EV-{index:02d}"
        parsed = parse_evidence(str(evidence_path), scenario_id)
        if not parsed:
            raise RuntimeError(f"Parser returned no events for {evidence_path}")
        for event in parsed:
            event["evidence_id"] = evidence_id
            events.append(event)
    return events


def _run_real_analysis(
    scenario_id: str,
    scenario_timezone: str,
    events: list[dict[str, Any]],
    evidence_files: list[dict[str, Any]],
    evidence_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Persist parsed events in an isolated DB and invoke the existing T8 service."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session, sessionmaker
    from sqlalchemy.pool import StaticPool

    from app.db.migrate import migrate
    from app.db.models import Case, Evidence, EventModel
    from app.db.models import EVIDENCE_QUARANTINED
    from app.db.session import verify_evidence
    from app.services.runs import diff_runs, execute_analysis_run, get_run_details

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    migrate(engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session: Session = session_factory()
    try:
        session.add(Case(case_id=scenario_id, name=scenario_id))
        events_by_evidence: dict[str, list[dict[str, Any]]] = {}
        for event in events:
            events_by_evidence.setdefault(event["evidence_id"], []).append(event)
        for index, evidence in enumerate(evidence_files, 1):
            evidence_id = f"{scenario_id}-EV-{index:02d}"
            path = evidence_root / evidence["path"]
            matching_events = events_by_evidence[evidence_id]
            sha256 = matching_events[0]["sha256"]
            session.add(Evidence(
                evidence_id=evidence_id,
                case_id=scenario_id,
                filename=evidence["filename"],
                sha256=sha256,
                size_bytes=path.stat().st_size,
                stored_path=str(path),
            ))
        session.flush()
        for event in events:
            session.add(EventModel(
                event_id=event["event_id"],
                case_id=scenario_id,
                evidence_id=event["evidence_id"],
                artifact_ref=event["artifact_ref"],
                sha256=event["sha256"],
                timestamp=_event_datetime(event["timestamp"]),
                source=event["source"],
                device=event.get("device"),
                actor=event.get("actor"),
                action=event["action"],
                object=event.get("object"),
                ip=event.get("ip"),
                location=event.get("location"),
                raw=event.get("raw"),
                parser_version=event.get("parser_version"),
                tz_assumption=event.get("tz_assumption"),
                family=event.get("family"),
            ))
        session.commit()

        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory(prefix="pramana-bench-run-") as run_directory:
            try:
                os.chdir(run_directory)
                run_result = execute_analysis_run(
                    session,
                    scenario_id,
                    assumptions={"case_timezone": scenario_timezone},
                )
                session.commit()
                details = get_run_details(session, run_result["run_id"])
                tamper_source = next(
                    item for item in evidence_files
                    if item["source"] == "browser"
                )
                tamper_path = evidence_root / tamper_source["path"]
                tamper_evidence = session.query(Evidence).filter(
                    Evidence.case_id == scenario_id,
                    Evidence.filename == tamper_source["filename"],
                ).one()
                with tamper_path.open("ab") as evidence_stream:
                    evidence_stream.write(b"\nsynthetic benchmark integrity mutation\n")
                verification = verify_evidence(
                    session,
                    tamper_evidence.evidence_id,
                    actor="PRAMANA synthetic benchmark",
                )
                session.commit()
                if verification["status"] != EVIDENCE_QUARANTINED:
                    raise RuntimeError(
                        f"T4 verification did not quarantine mutated synthetic evidence: "
                        f"{verification['status']}"
                    )
                if get_run_details(session, run_result["run_id"])["validity"] != "INVALIDATED":
                    raise RuntimeError("T8 did not invalidate the run after T4 quarantined its evidence")
                child_result = execute_analysis_run(
                    session,
                    scenario_id,
                    assumptions={"case_timezone": scenario_timezone},
                    parent_run_id=run_result["run_id"],
                )
                session.commit()
                run_diff = diff_runs(session, run_result["run_id"], child_result["run_id"])
                removed_descendants = set()
                for claim in run_diff["claims_diff"]["removed_claims"]:
                    if claim.get("type") != "SAME_OBJECT_FLOW":
                        continue
                    event_refs = [
                        ref_by_id
                        for edge in claim.get("edges", [])
                        if edge.get("ref_kind") == "event"
                        for ref_by_id in [
                            next(
                                (
                                    event["artifact_ref"]
                                    for event in events
                                    if event["event_id"] == edge.get("ref_id")
                                ),
                                None,
                            )
                        ]
                        if ref_by_id is not None
                    ]
                    for left_index, left in enumerate(event_refs):
                        for right in event_refs[left_index + 1:]:
                            if left != right:
                                removed_descendants.add(tuple(sorted((left, right))))
            finally:
                os.chdir(original_cwd)
        return run_result, details, sorted(removed_descendants)
    finally:
        session.close()
        engine.dispose()


def _actual_predictions(
    run_result: dict[str, Any],
    details: dict[str, Any],
    events: list[dict[str, Any]],
    invalidated_descendants: list[tuple[str, str]],
) -> dict[str, Any]:
    ref_by_id = {event["event_id"]: event["artifact_ref"] for event in events}
    claims = details.get("claims", [])
    predicted_links: set[tuple[str, str]] = set()
    valid_claim_ids = {str(claim["claim_id"]) for claim in claims if claim.get("claim_id")}
    lineage_total = 0
    lineage_resolved = 0
    contradictions: list[dict[str, Any]] = []
    for claim in claims:
        edges = claim.get("edges") or []
        event_refs: list[str] = []
        for edge in edges:
            kind, ref_id = edge.get("ref_kind"), str(edge.get("ref_id", ""))
            lineage_total += 1
            if kind == "event":
                resolved = ref_id in ref_by_id
                if resolved:
                    event_refs.append(ref_by_id[ref_id])
            elif kind == "claim":
                resolved = ref_id in valid_claim_ids
            else:
                resolved = False
            lineage_resolved += int(resolved)
        claim_type = claim.get("type")
        if claim_type in LINK_CLAIM_TYPES:
            for left_index, left in enumerate(event_refs):
                for right in event_refs[left_index + 1:]:
                    if left != right:
                        predicted_links.add(tuple(sorted((left, right))))
        if claim_type in {"LOCATION_CONFLICT", "SESSION_ORIGIN_MISMATCH"} and len(event_refs) >= 2:
            contradictions.append({"event_refs": event_refs[:2]})

    absence_classification: dict[str, str] = {}
    for hypothesis in run_result.get("ranked_hypotheses", []):
        for evaluation in hypothesis.get("evaluations", []):
            state = evaluation.get("state")
            if state in {"MISSING", "UNOBSERVABLE"}:
                absence_classification[str(evaluation.get("item_id"))] = state

    outcome = run_result.get("outcome")
    ranked = run_result.get("ranked_hypotheses", [])
    top_hypothesis = "UNDETERMINED" if outcome == "UNDETERMINED" else (
        ranked[0].get("id") if ranked else None
    )
    return {
        "links": sorted(predicted_links),
        "top_hypothesis": top_hypothesis,
        "contradictions": contradictions,
        "absence_classification": absence_classification,
        "claim_lineage": {"resolved": lineage_resolved, "total": lineage_total},
        "invalidated_descendants": invalidated_descendants,
        "outcome": outcome,
        "ranked_hypotheses": [
            {"id": hypothesis.get("id"), "rank": hypothesis.get("rank"), "status": hypothesis.get("status")}
            for hypothesis in ranked
        ],
        "reconstruction": _stable_output(run_result.get("reconstruction")),
        "claim_count": len(claims),
        "snapshot_available": details.get("snapshot_available"),
        "ranking_hash": run_result.get("ranking_hash"),
    }


def _prediction_rows(
    scenario: dict[str, Any],
    ground_truth: dict[str, Any],
    predictions: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = []
    for system, prediction in predictions.items():
        metrics = scenario_metrics(prediction, ground_truth)
        rows.append({
            "scenario_id": scenario["id"],
            "split": scenario["split"],
            "scenario_type": scenario["scenario_type"],
            "system": system,
            "event_count": ground_truth["event_count"],
            "prediction": prediction,
            "metrics": metrics,
        })
    return rows


def _write_report(
    results: dict[str, Any],
    report_path: Path,
) -> None:
    content = [
        "# PRAMANA Synthetic Benchmark Report",
        "",
        "Controlled synthetic evidence only; these results are not real-world accuracy claims.",
        "",
        f"- Scenarios evaluated: {results['scenario_count']}",
        f"- Events evaluated: {results['event_count']}",
        "- Development scenarios: 3",
        "- Held-out scenarios: 5",
        "- Reproducibility: scenario YAML seeds; use `make bench` or `python3 bench/run.py --seed N`.",
        "- `make bench` does not run tests. Run `python -m pytest bench/tests` separately; test results are intentionally not embedded in generated benchmark reports.",
        "",
        "## Results by split",
        "",
    ]
    metric_names = (
        ("link_precision", "Link precision (strict artifact references)"),
        ("link_recall", "Link recall (strict artifact references)"),
        ("link_precision_equivalence_aware", "Link precision (duplicate-equivalence aware)"),
        ("link_recall_equivalence_aware", "Link recall (duplicate-equivalence aware)"),
        ("decoy_false_positive_rate", "Decoy false-positive rate"),
        ("top_hypothesis_accuracy", "Top-hypothesis accuracy (includes correct UNDETERMINED)"),
        ("correct_undetermined_rate", "Correct UNDETERMINED rate"),
        ("over_claim_rate", "Over-claim rate"),
        ("selective_accuracy", "Selective accuracy (correct commitments / commitments)"),
        ("abstention_rate", "Abstention rate (UNDETERMINED on definite ground truth)"),
        ("contradiction_recall", "Contradiction recall"),
        ("missing_unobservable_accuracy", "MISSING vs UNOBSERVABLE accuracy"),
        ("claim_lineage_resolution_rate", "Claim lineage resolution"),
        ("tamper_invalidation_accuracy", "Tamper invalidation accuracy (strict artifact references)"),
        ("tamper_invalidation_equivalence_aware_accuracy", "Tamper invalidation accuracy (duplicate-equivalence aware)"),
    )
    for split in ("dev", "held-out"):
        content.extend((f"### {split}", ""))
        for system in SYSTEMS:
            aggregate = results["aggregate"][split][system]
            content.extend((
                f"#### {system} — {aggregate['scenario_count']} scenarios, {aggregate['event_count']} events",
                "",
                "| Metric | Raw count (numerator / denominator) | Percentage |",
                "|---|---:|---:|",
            ))
            for metric_key, label in metric_names:
                metric = aggregate["metrics"][metric_key]
                percentage = "N/A" if metric["percentage"] is None else f"{metric['percentage']:.2f}%"
                raw = f"{metric['numerator']} / {metric['denominator']}"
                if metric.get("unavailable_reason"):
                    raw += f" ({metric['unavailable_reason']})"
                content.append(f"| {label} | {raw} | {percentage} |")
            content.append("")
    content.extend((
        "## Metric interpretation",
        "",
        "- Strict link and tamper metrics compare exact artifact references. Equivalence-aware variants additionally normalize duplicate rows using the simulator's explicit `duplicate_rows` original-to-duplicate mapping; they are reported alongside, never instead of, strict scores.",
        "- Selective accuracy scores only non-UNDETERMINED commitments against defined ground truth. Abstention rate separately measures UNDETERMINED outputs on cases with a definite ground-truth hypothesis.",
        "",
        "## Known limitations",
        "",
        "- The scenarios are controlled synthetic fixtures and do not establish real-world forensic accuracy.",
        "- B1/B2 only predict event links; they do not produce hypothesis, contradiction, absence, lineage, or tamper predictions. Those metrics are reported as unavailable where no output exists.",
        "- The main scenario runner exercises T4 verification and T8 run-diff services directly on disposable generated evidence. The separate ROLE 2 integration test also exercises the public demo tamper endpoint, verification quarantine, Run A invalidation, and child-run diff through the API.",
        "- The T8 runner is database-backed and is invoked through the existing `execute_analysis_run` service in an isolated in-memory SQLite database. Missing T7/T8 dependencies cause the run to fail explicitly.",
        "- T7 source coverage currently uses normalized Event `source` values. Several CSV evidence families share `source=log`; family-specific scheduler/auth coverage may therefore not be distinguishable without a change outside T9/T10.",
        "- Ground truth is authored by the simulator independently of intelligence output. Scoring uses event artifact references, not generated claim IDs.",
        "",
        "## Reproducibility",
        "",
        "Run `make bench`. Use `python3 bench/run.py --seed 123` to override scenario seeds. Results are written to `bench/results/results.json`, `bench/results/results.csv`, and this report. Generated benchmark records are deterministic for the same YAML and seed; run IDs and execution timestamps are intentionally omitted from result artifacts.",
        "",
    ))
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(content), encoding="utf-8")


RECORD_KEY_FIELDS = ("scenario_id", "split", "scenario_type", "system")
SYSTEMS = ("B1", "B2", "PRAMANA")
METRIC_NAMES = (
    "link_precision",
    "link_recall",
    "link_precision_equivalence_aware",
    "link_recall_equivalence_aware",
    "decoy_false_positive_rate",
    "top_hypothesis_accuracy",
    "correct_undetermined_rate",
    "over_claim_rate",
    "selective_accuracy",
    "abstention_rate",
    "contradiction_recall",
    "missing_unobservable_accuracy",
    "claim_lineage_resolution_rate",
    "tamper_invalidation_accuracy",
    "tamper_invalidation_equivalence_aware_accuracy",
)


class DuplicateBenchmarkRecordError(RuntimeError):
    """Raised when benchmark records violate the per-key uniqueness invariant."""


def record_key(record: dict[str, Any]) -> tuple[str, str, str, str]:
    """Uniqueness key ``(scenario_id, split, scenario_type, system)``."""
    return tuple(str(record[field]) for field in RECORD_KEY_FIELDS)  # type: ignore[return-value]


def canonicalize_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return exactly one record per ``(scenario_id, split, scenario_type, system)``.

    * Conflicting duplicates (same key, different content) raise
      ``DuplicateBenchmarkRecordError`` naming the key and differing fields;
      neither the first nor the last record is silently preferred.
    * Exactly identical duplicates (canonical JSON equality) collapse to one.
    * Output order is deterministic (sorted by key).
    """
    canonical: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    serialized: dict[tuple[str, str, str, str], str] = {}
    for record in records:
        missing = [field for field in RECORD_KEY_FIELDS if field not in record]
        if missing:
            raise DuplicateBenchmarkRecordError(f"Benchmark record missing key fields {missing}")
        key = record_key(record)
        body = json.dumps(record, sort_keys=True, default=str)
        if key in canonical:
            if serialized[key] != body:
                existing = canonical[key]
                differing = sorted(
                    field for field in set(existing) | set(record)
                    if json.dumps(existing.get(field), sort_keys=True, default=str)
                    != json.dumps(record.get(field), sort_keys=True, default=str)
                )
                raise DuplicateBenchmarkRecordError(
                    "Conflicting benchmark records for key "
                    f"{dict(zip(RECORD_KEY_FIELDS, key))}: differing fields {differing}"
                )
            continue
        canonical[key] = record
        serialized[key] = body
    return [canonical[key] for key in sorted(canonical)]


def validate_unique_records(records: list[dict[str, Any]]) -> None:
    """Pre-write guard: fail if any uniqueness key appears more than once."""
    counts: dict[tuple[str, str, str, str], int] = {}
    for record in records:
        key = record_key(record)
        counts[key] = counts.get(key, 0) + 1
    dupes = {key: count for key, count in counts.items() if count > 1}
    if dupes:
        raise DuplicateBenchmarkRecordError(f"Duplicate benchmark record keys: {dupes}")


def csv_record(record: dict[str, Any]) -> dict[str, Any]:
    """Flatten one canonical record into its CSV row."""
    row: dict[str, Any] = {field: record[field] for field in RECORD_KEY_FIELDS}
    row["event_count"] = record["event_count"]
    for metric in METRIC_NAMES:
        for field in ("numerator", "denominator", "percentage"):
            row[f"{metric}_{field}"] = record["metrics"][metric][field]
    return row


def write_result_artifacts(results: dict[str, Any], results_dir: Path) -> None:
    """Overwrite results.json and results.csv from one validated canonical record set."""
    records = results["scenarios"]
    validate_unique_records(records)
    results_dir.mkdir(parents=True, exist_ok=True)
    json_path = results_dir / "results.json"
    csv_path = results_dir / "results.csv"
    json_path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    columns = [*RECORD_KEY_FIELDS, "event_count"]
    columns.extend(
        f"{metric}_{field}" for metric in METRIC_NAMES for field in ("numerator", "denominator", "percentage")
    )
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for record in records:
            writer.writerow(csv_record(record))


def run_benchmark(
    *,
    scenario_dir: Path = SCENARIO_DIR,
    results_dir: Path = DEFAULT_RESULTS_DIR,
    report_path: Path = DEFAULT_REPORT,
    seed: int | None = None,
) -> dict[str, Any]:
    """Generate evidence, run parser and T8 pipeline, evaluate, and save results."""
    results_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pramana-bench-evidence-") as temp_dir:
        evidence_root = Path(temp_dir)
        truth = generate(
            scenario_dir,
            evidence_root,
            ground_truth_path=None,
            seed=seed,
        )
        scenario_specs = {
            path.stem: __import__("yaml").safe_load(path.read_text(encoding="utf-8"))
            for path in sorted(scenario_dir.glob("*.yaml"))
        }
        rows: list[dict[str, Any]] = []
        for ground_truth in truth["scenarios"]:
            scenario = scenario_specs[ground_truth["scenario_id"]]
            events = _parse_scenario_events(
                ground_truth["scenario_id"],
                evidence_root,
                ground_truth["evidence_files"],
            )
            run_result, details, invalidated_descendants = _run_real_analysis(
                ground_truth["scenario_id"],
                scenario["timezone"],
                events,
                ground_truth["evidence_files"],
                evidence_root,
            )
            actual = _actual_predictions(run_result, details, events, invalidated_descendants)
            b1 = time_window_only(events)
            b2 = time_window_shared_identifier(events)
            predictions = {
                "B1": b1,
                "B2": b2,
                "PRAMANA": actual,
            }
            scenario_rows = _prediction_rows(scenario, ground_truth, predictions)
            for row in scenario_rows:
                row["ground_truth"] = ground_truth
            rows.extend(scenario_rows)

    expected_keys = {
        (gt["scenario_id"], gt["split"], gt["scenario_type"], system)
        for gt in truth["scenarios"]
        for system in SYSTEMS
    }
    rows = canonicalize_records([
        {
            "scenario_id": row["scenario_id"],
            "split": row["split"],
            "scenario_type": row["scenario_type"],
            "system": row["system"],
            "event_count": row["event_count"],
            "prediction": row["prediction"],
            "metrics": row["metrics"],
            "ground_truth": row["ground_truth"],
        }
        for row in rows
    ])
    produced_keys = {record_key(row) for row in rows}
    if produced_keys != expected_keys:
        raise DuplicateBenchmarkRecordError(
            "Benchmark record keys do not match scenario x system inputs: "
            f"missing={sorted(expected_keys - produced_keys)} "
            f"unexpected={sorted(produced_keys - expected_keys)}"
        )

    split_system_inputs = {
        split: {
            system: [
                (row["prediction"], row["ground_truth"])
                for row in rows
                if row["split"] == split and row["system"] == system
            ]
            for system in SYSTEMS
        }
        for split in ("dev", "held-out")
    }
    aggregate = {
        split: {
            system: aggregate_metrics(items)
            for system, items in systems.items()
        }
        for split, systems in split_system_inputs.items()
    }
    for split in ("dev", "held-out"):
        for system in SYSTEMS:
            selected = [row for row in rows if row["split"] == split and row["system"] == system]
            aggregate[split][system]["event_count"] = sum(row["event_count"] for row in selected)

    results = {
        "scenario_count": len(truth["scenarios"]),
        "event_count": sum(scenario["event_count"] for scenario in truth["scenarios"]),
        "scenarios": rows,
        "aggregate": aggregate,
    }
    write_result_artifacts(results, results_dir)

    _write_report({
        **results,
        "aggregate": {
            split: {
                system: {
                    **aggregate[split][system],
                    "scenario_count": sum(
                        1 for scenario in truth["scenarios"] if scenario["split"] == split
                    ),
                }
                for system in SYSTEMS
            }
            for split in ("dev", "held-out")
        },
    }, report_path)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario-dir", type=Path, default=SCENARIO_DIR)
    parser.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS_DIR)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--seed", type=int)
    args = parser.parse_args()
    results = run_benchmark(
        scenario_dir=args.scenario_dir,
        results_dir=args.results_dir,
        report_path=args.report,
        seed=args.seed,
    )
    print(
        f"Evaluated {results['scenario_count']} scenarios and "
        f"{results['event_count']} events; results: {args.results_dir}"
    )


if __name__ == "__main__":
    main()
