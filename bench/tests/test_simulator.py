from __future__ import annotations

import ast
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml
from bench.gen.simulator import ROOT, SCENARIO_DIR, generate


def _parser():
    parser_dir = ROOT / "evidence-engine"
    if str(parser_dir) not in sys.path:
        sys.path.insert(0, str(parser_dir))
    from parsers import parse_evidence

    return parse_evidence


def test_seeded_generation_is_reproducible_and_seed_sensitive(tmp_path: Path):
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    changed_dir = tmp_path / "changed"
    first_truth = generate(
        SCENARIO_DIR,
        first_dir,
        tmp_path / "first-ground-truth.json",
        seed=444,
    )
    second_truth = generate(
        SCENARIO_DIR,
        second_dir,
        tmp_path / "second-ground-truth.json",
        seed=444,
    )
    generate(
        SCENARIO_DIR,
        changed_dir,
        tmp_path / "changed-ground-truth.json",
        seed=445,
    )

    assert first_truth == second_truth
    for generated in first_dir.rglob("*"):
        if generated.is_file():
            assert generated.read_bytes() == (second_dir / generated.relative_to(first_dir)).read_bytes()
    assert (first_dir / "CASE-DEMO-IST/evidence/endpoint_system_log.csv").read_bytes() != (
        changed_dir / "CASE-DEMO-IST/evidence/endpoint_system_log.csv"
    ).read_bytes()


def test_generated_evidence_parses_and_ground_truth_refs_resolve(tmp_path: Path):
    parse_evidence = _parser()
    truth = generate(
        SCENARIO_DIR,
        tmp_path / "evidence",
        tmp_path / "ground-truth.json",
        seed=712,
    )
    assert len(truth["scenarios"]) == 8
    assert sum(item["split"] == "dev" for item in truth["scenarios"]) == 3
    assert sum(item["split"] == "held-out" for item in truth["scenarios"]) == 5
    specs = [
        yaml.safe_load(path.read_text(encoding="utf-8"))
        for path in SCENARIO_DIR.glob("*.yaml")
    ]
    assert sum(item["scenario_type"] == "malicious" for item in specs) == 4
    assert sum(item["scenario_type"] == "benign_looking" for item in specs) == 2
    assert sum(item["scenario_type"] == "ambiguous" for item in specs) == 2
    assert any(item["timezone"] == "Asia/Kolkata" for item in specs)
    assert any(30 in item["clock_offsets_minutes"].values() for item in specs)

    for scenario in truth["scenarios"]:
        evidence_root = tmp_path / "evidence"
        actual_refs = set()
        parsed_by_ref = {}
        total_events = 0
        for source in scenario["evidence_files"]:
            events = parse_evidence(
                str(evidence_root / source["path"]),
                scenario["scenario_id"],
            )
            total_events += len(events)
            for event in events:
                actual_refs.add(event["artifact_ref"])
                parsed_by_ref[event["artifact_ref"]] = event
        assert 100 <= total_events <= 300
        assert total_events == scenario["event_count"]
        truth_refs = set(scenario["stage_labels"])
        truth_refs.update(scenario["background_unassigned_events"])
        truth_refs.update(scenario["decoy_events"])
        truth_refs.update(row["duplicate"] for row in scenario["duplicate_rows"])
        assert truth_refs <= actual_refs
        assert set(scenario["stage_labels"]).isdisjoint(scenario["background_unassigned_events"])
        assert set(scenario["stage_labels"]) | set(scenario["background_unassigned_events"]) == actual_refs
        assert all(
            link["from"] in actual_refs and link["to"] in actual_refs
            for link in scenario["true_links"]
        )
        assert {item["severity"] for item in scenario["contradictions"]} == {"hard", "soft"}
        for duplicate in scenario["duplicate_rows"]:
            first = parsed_by_ref[duplicate["duplicate"]]
            original = parsed_by_ref[duplicate["original"]]
            assert first["raw"] == original["raw"]

        spec = yaml.safe_load((SCENARIO_DIR / f"{scenario['scenario_id']}.yaml").read_text())
        gap = spec["coverage_gap"]
        zone = ZoneInfo(spec["timezone"])
        gap_start = datetime(2026, 10, 17, 16, tzinfo=zone) + timedelta(
            minutes=gap["start_minute"] + spec["clock_offsets_minutes"][gap["source"]]
        )
        gap_end = datetime(2026, 10, 17, 16, tzinfo=zone) + timedelta(
            minutes=gap["end_minute"] + spec["clock_offsets_minutes"][gap["source"]]
        )
        gap_events = [
            event
            for source in scenario["evidence_files"]
            if source["source"] == gap["source"]
            for event in parse_evidence(str(evidence_root / source["path"]), scenario["scenario_id"])
        ]
        assert all(
            not gap_start <= datetime.fromisoformat(event["raw"]["timestamp"]) <= gap_end
            for event in gap_events
        )


def test_demo_ist_contains_five_parser_supported_evidence_sources(tmp_path: Path):
    parse_evidence = _parser()
    truth = generate(
        SCENARIO_DIR,
        tmp_path / "demo",
        tmp_path / "ground-truth.json",
        scenario_id="CASE-DEMO-IST",
    )
    scenario = truth["scenarios"][0]
    assert scenario["scenario_id"] == "CASE-DEMO-IST"
    assert len(scenario["evidence_files"]) == 5
    assert {item["source"] for item in scenario["evidence_files"]} == {
        "endpoint", "browser", "phone", "vpn", "scheduler"
    }
    event_counts = {}
    for source in scenario["evidence_files"]:
        events = parse_evidence(str(tmp_path / "demo" / source["path"]), "CASE-DEMO-IST")
        event_counts[source["source"]] = len(events)
    assert all(count > 0 for count in event_counts.values())
    assert scenario["absence_classification"]["H2-EXP-2"] == "MISSING"
    archive = next(
        event
        for source in scenario["evidence_files"]
        if source["source"] == "endpoint"
        for event in parse_evidence(str(tmp_path / "demo" / source["path"]), "CASE-DEMO-IST")
        if event["action"] == "archive_create"
    )
    scheduler_events = next(
        parse_evidence(str(tmp_path / "demo" / source["path"]), "CASE-DEMO-IST")
        for source in scenario["evidence_files"]
        if source["source"] == "scheduler"
    )
    archive_time = datetime.fromisoformat(archive["timestamp"].replace("Z", "+00:00"))
    scheduler_times = [
        datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        for event in scheduler_events
    ]
    assert min(scheduler_times) < archive_time < max(scheduler_times)
    assert not any(
        event["action"] in {"backup_job", "scheduled_backup"}
        and abs(
            (
                datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                - archive_time
            ).total_seconds()
        ) <= 60
        for event in scheduler_events
    )


def test_simulator_has_no_intelligence_imports():
    source = (ROOT / "bench/gen/simulator.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    imported.update(
        node.module.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    )
    assert "intelligence" not in imported


def test_default_ground_truth_is_json_if_present():
    generated_truth = SCENARIO_DIR / "ground_truth.json"
    if generated_truth.exists():
        payload = json.loads(generated_truth.read_text(encoding="utf-8"))
        assert len(payload["scenarios"]) == 8
