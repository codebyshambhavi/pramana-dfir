"""Generate deterministic synthetic evidence for PRAMANA benchmarks.

The generator writes only formats supported by evidence-engine: system/browser
CSV and chat JSON. It deliberately has no dependency on the intelligence package.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import yaml


ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = ROOT / "bench"
SCENARIO_DIR = BENCH_DIR / "scenarios"
DEFAULT_OUTPUT_DIR = BENCH_DIR / "generated"
DEFAULT_GROUND_TRUTH = SCENARIO_DIR / "ground_truth.json"
SOURCES = ("endpoint", "browser", "phone", "vpn", "scheduler")


def _read_scenarios(scenario_dir: Path) -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []
    for path in sorted(scenario_dir.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError(f"Scenario must be a YAML object: {path}")
        if data.get("id") != path.stem:
            raise ValueError(f"Scenario id must match filename: {path}")
        count = data.get("event_count")
        if not isinstance(count, int) or not 100 <= count <= 300:
            raise ValueError(f"{path}: event_count must be between 100 and 300")
        sources = data.get("evidence_sources")
        if not isinstance(sources, list) or not 4 <= len(sources) <= 5:
            raise ValueError(f"{path}: evidence_sources must contain four or five sources")
        if len(set(sources)) != len(sources) or not set(sources) <= set(SOURCES):
            raise ValueError(f"{path}: unknown or duplicate evidence source")
        if data.get("split") not in {"dev", "held-out"}:
            raise ValueError(f"{path}: split must be dev or held-out")
        scenarios.append(data)
    if not scenarios:
        raise ValueError(f"No scenario YAML files found in {scenario_dir}")
    return scenarios


def _local_time(base: datetime, minute: int, offset: int) -> str:
    return (base + timedelta(minutes=minute + offset)).isoformat(timespec="seconds")


def _row(
    timestamp: str,
    action: str,
    actor: str,
    device: str,
    ip: str,
    obj: str,
    *,
    url: str | None = None,
    gps: dict[str, float] | None = None,
    truth_stage: str | None = None,
    key: str | None = None,
    decoy: bool = False,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "timestamp": timestamp,
        "action": action,
        "actor": actor,
        "device": device,
        "ip": ip,
        "object": obj,
        "_truth_stage": truth_stage,
        "_truth_key": key,
        "_decoy": decoy,
    }
    if url is not None:
        row["url"] = url
    if gps is not None:
        row["device_gps"] = gps
    return row


def _source_filename(source: str) -> str:
    return {
        "endpoint": "endpoint_system_log.csv",
        "browser": "browser_history.csv",
        "phone": "phone_chat.json",
        "vpn": "vpn_authentication.csv",
        "scheduler": "backup_scheduler.csv",
    }[source]


def _generate_scenario(
    scenario: dict[str, Any],
    output_dir: Path,
    seed_override: int | None = None,
) -> dict[str, Any]:
    scenario_id = str(scenario["id"])
    seed = int(scenario["seed"] if seed_override is None else seed_override)
    rng = random.Random(seed)
    zone = ZoneInfo(str(scenario["timezone"]))
    base = datetime(2026, 10, 17, 16, 0, tzinfo=zone)
    actor = str(scenario["actor"])
    device = str(scenario["device"])
    file_name = str(scenario["file"])
    source_names = list(scenario["evidence_sources"])
    offsets = scenario["clock_offsets_minutes"]
    coverage_gap = scenario["coverage_gap"]
    count = int(scenario["event_count"])
    duplicate_count = int(scenario.get("duplicate_count", 0))
    if duplicate_count < 1 or duplicate_count >= count:
        raise ValueError(f"{scenario_id}: duplicate_count must be in [1, event_count)")

    counts = {name: (count - duplicate_count) // len(source_names) for name in source_names}
    for source in source_names[: (count - duplicate_count) % len(source_names)]:
        counts[source] += 1
    rows_by_source: dict[str, list[dict[str, Any]]] = {name: [] for name in source_names}
    by_key: dict[str, tuple[str, dict[str, Any]]] = {}

    def add(source: str, minute: int, action: str, obj: str, stage: str | None, key: str | None,
            *, row_actor: str = actor, row_device: str = device, ip: str | None = None,
            url: str | None = None, gps: dict[str, float] | None = None, decoy: bool = False) -> None:
        if source not in rows_by_source or len(rows_by_source[source]) >= counts[source]:
            return
        ip_value = ip or "198.51.100.42"
        timestamp = _local_time(base, minute, int(offsets.get(source, 0)))
        existing_timestamps = {
            existing["timestamp"]
            for existing_rows in rows_by_source.values()
            for existing in existing_rows
        }
        candidate_time = datetime.fromisoformat(timestamp)
        while timestamp in existing_timestamps:
            candidate_time += timedelta(seconds=1)
            timestamp = candidate_time.isoformat(timespec="seconds")
        row = _row(
            timestamp,
            action, row_actor, row_device, ip_value, obj,
            url=url, gps=gps, truth_stage=stage, key=key, decoy=decoy,
        )
        rows_by_source[source].append(row)
        if key:
            by_key[key] = (source, row)

    # Cross-source incident stages used by independently-authored ground truth.
    vpn_ip = "203.0.113.66" if scenario.get("correct_hypothesis") == "H3" else None
    add("vpn", 380, "login", file_name, "access", "vpn_access", ip=vpn_ip)
    add("endpoint", 390, "file_access", file_name, "access", "endpoint_access")
    add("phone", 395, "message_sent", f"Discussed {file_name}", "planning", "phone_message",
        gps={"lat": 37.7749, "lon": -122.4194})
    add("endpoint", 420, "archive_create", file_name, "staging", "archive")
    add("browser", 430, "visit", "external-storage.example", "exfiltration", "browser_visit",
        url="https://external-storage.example/")
    add("browser", 435, "upload", f"https://external-storage.example/{file_name}", "exfiltration",
        "upload", url=f"https://external-storage.example/{file_name}")
    scheduled_minute = 420 if scenario.get("correct_hypothesis") == "H2" else 120
    if "scheduler" in rows_by_source:
        add("scheduler", scheduled_minute, "scheduled_backup" if scheduled_minute == 420 else "backup_job",
            file_name, "verification" if scheduled_minute == 420 else None, "scheduled_job")
        add("scheduler", 300, "coverage_window_start", "backup scheduler coverage", None, None)
        add("scheduler", 480, "coverage_window_end", "backup scheduler coverage", None, None)

    # Contradictory attribution and a softer cross-source timing discrepancy.
    hard_key = None
    if "endpoint" in rows_by_source:
        hard_key = "hard_contradiction"
        add("endpoint", 422, "archive_create", file_name, None, hard_key,
            row_actor=f"unknown.{rng.randint(10, 99)}", row_device=f"unrecognized-{rng.randint(1, 9)}")
    soft_key = None
    if "vpn" in rows_by_source:
        soft_key = "soft_contradiction"
        add("vpn", 428, "session_refresh", file_name, None, soft_key)

    # Fill remaining rows with ordinary activity, including nearby decoys.
    for source in source_names:
        while len(rows_by_source[source]) < counts[source]:
            idx = len(rows_by_source[source])
            minute = rng.randint(0, 480)
            if source == coverage_gap["source"]:
                gap_start = int(coverage_gap["start_minute"])
                gap_end = int(coverage_gap["end_minute"])
                if gap_start <= minute <= gap_end:
                    continue
            is_decoy = idx < max(1, int(scenario.get("decoy_count", 0)) // len(source_names))
            if is_decoy:
                minute = rng.choice((418, 421, 424, 432, 438))
            actions = ("login", "file_read", "process_start", "heartbeat", "search", "sync_check")
            action = rng.choice(actions)
            obj = rng.choice(
                ("/home/user/notes.txt", "calendar", "internal-wiki", "health-check", "printer-status")
            )
            background_actor = actor
            background_device = device
            if scenario.get("correct_hypothesis") == "H3":
                background_actor = f"service.{source}.{idx:03d}"
                background_device = f"{device}-{source}-{idx % 4 + 1}"
            if source == "browser":
                obj = f"https://intranet.example/{rng.choice(('home', 'docs', 'calendar', 'status'))}"
                url = obj
            else:
                url = None
            add(
                source,
                minute,
                action,
                obj,
                None,
                None,
                row_actor=background_actor,
                row_device=background_device,
                url=url,
                decoy=is_decoy,
            )

    # Add exact duplicate records as separate evidence rows, preserving duplicate content.
    for index in range(duplicate_count):
        source = source_names[index % len(source_names)]
        candidates = rows_by_source[source]
        original = candidates[index % len(candidates)]
        duplicate = dict(original)
        duplicate["_duplicate_of"] = original
        rows_by_source[source].append(duplicate)

    # Assign parser-facing row references only after final source ordering.
    ref_by_row: dict[int, str] = {}
    refs_by_key: dict[str, str] = {}
    decoy_refs: list[str] = []
    duplicate_refs: list[dict[str, str]] = []
    stage_labels: dict[str, str] = {}
    evidence_dir = output_dir / scenario_id / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_files: list[dict[str, Any]] = []
    for source in source_names:
        rows = sorted(
            rows_by_source[source],
            key=lambda r: (r["timestamp"], str(r.get("_truth_key") or ""), str(r["action"])),
        )
        filename = _source_filename(source)
        refs: list[str] = []
        for row_number, row in enumerate(rows, 1):
            ref = f"{filename}#{'item' if source == 'phone' else 'row'}={row_number - 1 if source == 'phone' else row_number}"
            refs.append(ref)
            if row.get("_truth_key"):
                refs_by_key[str(row["_truth_key"])] = ref
            if row.get("_truth_stage"):
                stage_labels[ref] = str(row["_truth_stage"])
            if row.get("_decoy"):
                decoy_refs.append(ref)
            original = row.get("_duplicate_of")
            if original is not None:
                original_ref = next(
                    (
                        f"{filename}#{'item' if source == 'phone' else 'row'}={pos if source == 'phone' else pos + 1}"
                        for pos, existing in enumerate(rows)
                        if existing is original
                    ),
                    "",
                )
                duplicate_refs.append({"duplicate": ref, "original": original_ref})

        path = evidence_dir / filename
        clean_rows = [{k: v for k, v in row.items() if not k.startswith("_")} for row in rows]
        if source == "phone":
            path.write_text(json.dumps(clean_rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        else:
            headers = (
                ["timestamp", "action", "url", "actor", "device", "ip", "object"]
                if source == "browser"
                else ["timestamp", "action", "actor", "device", "ip", "object"]
            )
            with path.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=headers, extrasaction="ignore", lineterminator="\n")
                writer.writeheader()
                writer.writerows(clean_rows)
        evidence_files.append({
            "source": source,
            "path": path.relative_to(output_dir).as_posix(),
            "filename": filename,
            "event_count": len(rows),
        })

    true_links = [
        {"from": refs_by_key[first], "to": refs_by_key[second], "link_type": "incident_sequence"}
        for first, second in (
            ("vpn_access", "endpoint_access"),
            ("endpoint_access", "archive"),
            ("archive", "upload"),
            ("phone_message", "archive"),
        )
        if first in refs_by_key and second in refs_by_key
    ]
    tamper_descendants = [
        {"from": link["from"], "to": link["to"]}
        for link in true_links
        if link["from"].startswith("browser_history.csv#")
        or link["to"].startswith("browser_history.csv#")
    ]
    contradictions: list[dict[str, Any]] = []
    if hard_key in refs_by_key:
        hard_row = by_key[hard_key][1]
        archive_row = by_key["archive"][1]
        contradictions.append({
            "severity": "hard",
            "type": scenario["contradictions"]["hard"]["type"],
            "event_refs": [refs_by_key["archive"], refs_by_key[hard_key]],
            "conflicting_fields": ["actor", "device"],
            "observed_values": {
                "archive": {"actor": archive_row["actor"], "device": archive_row["device"]},
                "contradictory_event": {"actor": hard_row["actor"], "device": hard_row["device"]},
            },
        })
    if soft_key in refs_by_key:
        upload_time = datetime.fromisoformat(by_key["upload"][1]["timestamp"])
        soft_time = datetime.fromisoformat(by_key[soft_key][1]["timestamp"])
        contradictions.append({
            "severity": "soft",
            "type": scenario["contradictions"]["soft"]["type"],
            "event_refs": [refs_by_key["upload"], refs_by_key[soft_key]],
            "observed_timestamp_delta_seconds": int((soft_time - upload_time).total_seconds()),
        })

    coverage = scenario["coverage_gap"]
    gt = {
        "scenario_id": scenario_id,
        "split": scenario["split"],
        "scenario_type": scenario["scenario_type"],
        "seed": seed,
        "event_count": sum(item["event_count"] for item in evidence_files),
        "evidence_sources": [item["source"] for item in evidence_files],
        "evidence_files": evidence_files,
        "true_links": true_links,
        "tamper_test": {"evidence_source": "browser"},
        "tamper_descendants": tamper_descendants,
        "stage_labels": stage_labels,
        "background_unassigned_events": sorted(
            ref for ref in (
                f"{item['filename']}#{'item' if item['source'] == 'phone' else 'row'}={i if item['source'] == 'phone' else i + 1}"
                for item in evidence_files
                for i in range(item["event_count"])
            )
            if ref not in stage_labels
        ),
        "decoy_events": sorted(decoy_refs),
        "duplicate_rows": duplicate_refs,
        "coverage_gap": {
            **coverage,
            "classification": "UNOBSERVABLE",
        },
        "contradictions": contradictions,
        "expected_missing_items": scenario.get("missing_items", []),
        "absence_classification": {
            item["item"]: item["expected_absence"] for item in scenario.get("missing_items", [])
        },
        "correct_hypothesis": scenario["correct_hypothesis"],
        "hypotheses": scenario.get("hypotheses", []),
    }
    return gt


def generate(
    scenario_dir: Path = SCENARIO_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    ground_truth_path: Path | None = DEFAULT_GROUND_TRUTH,
    *,
    seed: int | None = None,
    scenario_id: str | None = None,
) -> dict[str, Any]:
    """Generate evidence and ground truth for scenarios, returning the truth object."""
    scenarios = _read_scenarios(scenario_dir)
    if scenario_id is not None:
        scenarios = [item for item in scenarios if item["id"] == scenario_id]
        if not scenarios:
            raise ValueError(f"Unknown scenario id: {scenario_id}")
    scenario_results = [
        _generate_scenario(item, output_dir, seed_override=seed)
        for item in scenarios
    ]
    truth = {"schema_version": 1, "scenarios": scenario_results}
    if ground_truth_path is not None:
        ground_truth_path.parent.mkdir(parents=True, exist_ok=True)
        ground_truth_path.write_text(
            json.dumps(truth, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return truth


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario-dir", type=Path, default=SCENARIO_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--ground-truth", type=Path, default=DEFAULT_GROUND_TRUTH)
    parser.add_argument("--seed", type=int)
    parser.add_argument("--scenario-id")
    args = parser.parse_args()
    truth = generate(
        args.scenario_dir,
        args.output_dir,
        args.ground_truth,
        seed=args.seed,
        scenario_id=args.scenario_id,
    )
    print(f"Generated {len(truth['scenarios'])} scenario(s) in {args.output_dir}")


if __name__ == "__main__":
    main()
