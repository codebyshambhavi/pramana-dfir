"""Benchmark result integrity: one canonical record per uniqueness key (PR #18 review)."""
from __future__ import annotations

import copy
import csv
import json
from pathlib import Path

import pytest

from bench.gen.simulator import SCENARIO_DIR
from bench.run import (
    RECORD_KEY_FIELDS,
    SYSTEMS,
    DuplicateBenchmarkRecordError,
    canonicalize_records,
    csv_record,
    record_key,
    run_benchmark,
    validate_unique_records,
    write_result_artifacts,
)

COMMITTED_RESULTS = Path(__file__).resolve().parents[1] / "results"


def _record(scenario_id: str = "CASE-X", system: str = "PRAMANA", value: int = 1) -> dict:
    metrics = {
        name: {"numerator": value, "denominator": 2, "percentage": value * 50.0}
        for name in (
            "link_precision", "link_recall", "link_precision_equivalence_aware",
            "link_recall_equivalence_aware", "decoy_false_positive_rate",
            "top_hypothesis_accuracy", "correct_undetermined_rate", "over_claim_rate",
            "selective_accuracy", "abstention_rate", "contradiction_recall",
            "missing_unobservable_accuracy", "claim_lineage_resolution_rate",
            "tamper_invalidation_accuracy", "tamper_invalidation_equivalence_aware_accuracy",
        )
    }
    return {
        "scenario_id": scenario_id,
        "split": "dev",
        "scenario_type": "malicious",
        "system": system,
        "event_count": 10,
        "prediction": {},
        "metrics": metrics,
        "ground_truth": {},
    }


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def _assert_csv_json_consistent(results_dir: Path) -> None:
    data = json.loads((results_dir / "results.json").read_text(encoding="utf-8"))
    csv_rows = _read_csv(results_dir / "results.csv")
    json_keys = [record_key(r) for r in data["scenarios"]]
    csv_keys = [tuple(row[f] for f in RECORD_KEY_FIELDS) for row in csv_rows]
    assert len(json_keys) == len(set(json_keys)), "duplicate keys in JSON"
    assert len(csv_keys) == len(set(csv_keys)), "duplicate keys in CSV"
    assert set(json_keys) == set(csv_keys)
    json_by_key = {record_key(r): csv_record(r) for r in data["scenarios"]}
    for row in csv_rows:
        expected = json_by_key[tuple(row[f] for f in RECORD_KEY_FIELDS)]
        for column, value in expected.items():
            rendered = "" if value is None else str(value)
            assert row[column] == rendered, (column, row[column], rendered)


# --- unit-level guarantees ---------------------------------------------------

def test_conflicting_duplicate_keys_are_reported():
    with pytest.raises(DuplicateBenchmarkRecordError) as excinfo:
        canonicalize_records([_record(value=1), _record(value=0)])
    message = str(excinfo.value)
    assert "CASE-X" in message and "PRAMANA" in message and "metrics" in message


def test_identical_duplicates_produce_single_output_row(tmp_path: Path):
    rec = _record()
    records = canonicalize_records([rec, copy.deepcopy(rec), _record(system="B1")])
    assert [record_key(r) for r in records] == [
        ("CASE-X", "dev", "malicious", "B1"),
        ("CASE-X", "dev", "malicious", "PRAMANA"),
    ]
    write_result_artifacts({"scenarios": records}, tmp_path)
    assert len(_read_csv(tmp_path / "results.csv")) == 2
    _assert_csv_json_consistent(tmp_path)


def test_writer_refuses_duplicate_keys(tmp_path: Path):
    with pytest.raises(DuplicateBenchmarkRecordError):
        write_result_artifacts({"scenarios": [_record(), _record()]}, tmp_path)
    assert not (tmp_path / "results.csv").exists()


def test_validate_unique_records_accepts_distinct_keys():
    validate_unique_records([_record("A"), _record("B"), _record("A", system="B2")])


def test_regeneration_overwrites_stale_rows(tmp_path: Path):
    write_result_artifacts({"scenarios": [_record("OLD-1"), _record("OLD-2")]}, tmp_path)
    write_result_artifacts({"scenarios": [_record("NEW-1")]}, tmp_path)
    rows = _read_csv(tmp_path / "results.csv")
    assert [row["scenario_id"] for row in rows] == ["NEW-1"]
    data = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert [r["scenario_id"] for r in data["scenarios"]] == ["NEW-1"]


# --- committed artifacts -------------------------------------------------------

def test_committed_artifacts_have_one_record_per_key():
    data = json.loads((COMMITTED_RESULTS / "results.json").read_text(encoding="utf-8"))
    expected = {
        (gt["scenario_id"], gt["split"], gt["scenario_type"], system)
        for gt in {r["scenario_id"]: r["ground_truth"] for r in data["scenarios"]}.values()
        for system in SYSTEMS
    }
    keys = [record_key(r) for r in data["scenarios"]]
    assert sorted(keys) == sorted(expected)
    _assert_csv_json_consistent(COMMITTED_RESULTS)


# --- end-to-end -----------------------------------------------------------------

def test_benchmark_runs_are_deterministic_and_clean(tmp_path: Path):
    first, second = tmp_path / "first", tmp_path / "second"
    # Pre-seed stale content that must not survive regeneration.
    first.mkdir()
    (first / "results.csv").write_text("scenario_id,split,scenario_type,system\nSTALE,dev,x,B1\n")

    res1 = run_benchmark(
        scenario_dir=SCENARIO_DIR,
        results_dir=first,
        report_path=tmp_path / "r1.md",
        seed=7,
    )
    res2 = run_benchmark(
        scenario_dir=SCENARIO_DIR,
        results_dir=second,
        report_path=tmp_path / "r2.md",
        seed=7,
    )

    scenario_count = len(list(SCENARIO_DIR.glob("*.yaml")))
    assert len(res1["scenarios"]) == scenario_count * len(SYSTEMS)
    for name in ("results.json", "results.csv"):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    assert (tmp_path / "r1.md").read_text() == (tmp_path / "r2.md").read_text()
    assert "STALE" not in (first / "results.csv").read_text()
    _assert_csv_json_consistent(first)
    assert res1 == res2
