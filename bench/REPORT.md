# PRAMANA Synthetic Benchmark Report

Controlled synthetic evidence only; these results are not real-world accuracy claims.

- Scenarios evaluated: 8
- Events evaluated: 1520
- Development scenarios: 3
- Held-out scenarios: 5
- Reproducibility: scenario YAML seeds; use `make bench` or `python3 bench/run.py --seed N`.
- `make bench` does not run tests. Validation performed for this deliverable: 11 benchmark tests passed; the existing evidence-engine suite reported 95 passed and 1 unrelated failure (`test_sample_case_events_are_valid_and_contain_three_planted_items`, which expects a generated event ID in the untouched sample ground-truth markdown); 0 skipped.

## Results by split

### dev

#### B1 — 3 scenarios, 420 events

| Metric | Raw count (numerator / denominator) | Percentage |
|---|---:|---:|
| Link precision | 0 / 12 | 0.00% |
| Link recall | 0 / 10 | 0.00% |
| Decoy false-positive rate | 0 / 3 | 0.00% |
| Top-hypothesis accuracy | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Correct UNDETERMINED rate | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Over-claim rate | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Contradiction recall | 0 / 0 (system did not produce contradiction predictions) | N/A |
| MISSING vs UNOBSERVABLE accuracy | 0 / 0 (system did not produce absence classifications) | N/A |
| Claim lineage resolution | 0 / 0 (system did not expose claim lineage counts) | N/A |
| Tamper invalidation accuracy | 0 / 0 (system did not produce tamper invalidation predictions) | N/A |

#### B2 — 3 scenarios, 420 events

| Metric | Raw count (numerator / denominator) | Percentage |
|---|---:|---:|
| Link precision | 0 / 12 | 0.00% |
| Link recall | 0 / 10 | 0.00% |
| Decoy false-positive rate | 0 / 3 | 0.00% |
| Top-hypothesis accuracy | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Correct UNDETERMINED rate | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Over-claim rate | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Contradiction recall | 0 / 0 (system did not produce contradiction predictions) | N/A |
| MISSING vs UNOBSERVABLE accuracy | 0 / 0 (system did not produce absence classifications) | N/A |
| Claim lineage resolution | 0 / 0 (system did not expose claim lineage counts) | N/A |
| Tamper invalidation accuracy | 0 / 0 (system did not produce tamper invalidation predictions) | N/A |

#### PRAMANA — 3 scenarios, 420 events

| Metric | Raw count (numerator / denominator) | Percentage |
|---|---:|---:|
| Link precision | 3 / 6 | 50.00% |
| Link recall | 3 / 10 | 30.00% |
| Decoy false-positive rate | 0 / 3 | 0.00% |
| Top-hypothesis accuracy | 1 / 3 | 33.33% |
| Correct UNDETERMINED rate | 0 / 1 | 0.00% |
| Over-claim rate | 1 / 1 | 100.00% |
| Contradiction recall | 0 / 6 | 0.00% |
| MISSING vs UNOBSERVABLE accuracy | 0 / 3 | 0.00% |
| Claim lineage resolution | 429 / 429 | 100.00% |
| Tamper invalidation accuracy | 0 / 3 | 0.00% |

### held-out

#### B1 — 5 scenarios, 1100 events

| Metric | Raw count (numerator / denominator) | Percentage |
|---|---:|---:|
| Link precision | 0 / 20 | 0.00% |
| Link recall | 0 / 18 | 0.00% |
| Decoy false-positive rate | 0 / 34 | 0.00% |
| Top-hypothesis accuracy | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Correct UNDETERMINED rate | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Over-claim rate | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Contradiction recall | 0 / 0 (system did not produce contradiction predictions) | N/A |
| MISSING vs UNOBSERVABLE accuracy | 0 / 0 (system did not produce absence classifications) | N/A |
| Claim lineage resolution | 0 / 0 (system did not expose claim lineage counts) | N/A |
| Tamper invalidation accuracy | 0 / 0 (system did not produce tamper invalidation predictions) | N/A |

#### B2 — 5 scenarios, 1100 events

| Metric | Raw count (numerator / denominator) | Percentage |
|---|---:|---:|
| Link precision | 0 / 20 | 0.00% |
| Link recall | 0 / 18 | 0.00% |
| Decoy false-positive rate | 0 / 34 | 0.00% |
| Top-hypothesis accuracy | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Correct UNDETERMINED rate | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Over-claim rate | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Contradiction recall | 0 / 0 (system did not produce contradiction predictions) | N/A |
| MISSING vs UNOBSERVABLE accuracy | 0 / 0 (system did not produce absence classifications) | N/A |
| Claim lineage resolution | 0 / 0 (system did not expose claim lineage counts) | N/A |
| Tamper invalidation accuracy | 0 / 0 (system did not produce tamper invalidation predictions) | N/A |

#### PRAMANA — 5 scenarios, 1100 events

| Metric | Raw count (numerator / denominator) | Percentage |
|---|---:|---:|
| Link precision | 5 / 10 | 50.00% |
| Link recall | 5 / 18 | 27.78% |
| Decoy false-positive rate | 0 / 34 | 0.00% |
| Top-hypothesis accuracy | 2 / 5 | 40.00% |
| Correct UNDETERMINED rate | 0 / 1 | 0.00% |
| Over-claim rate | 1 / 1 | 100.00% |
| Contradiction recall | 0 / 10 | 0.00% |
| MISSING vs UNOBSERVABLE accuracy | 1 / 5 | 20.00% |
| Claim lineage resolution | 1116 / 1116 | 100.00% |
| Tamper invalidation accuracy | 0 / 5 | 0.00% |

## Known limitations

- The scenarios are controlled synthetic fixtures and do not establish real-world forensic accuracy.
- B1/B2 only predict event links; they do not produce hypothesis, contradiction, absence, lineage, or tamper predictions. Those metrics are reported as unavailable where no output exists.
- Tamper invalidation is exercised only against disposable generated evidence by calling the existing T4 verification service and T8 run-diff service; the benchmark does not implement the demo tamper endpoint or quarantine behavior.
- The T8 runner is database-backed and is invoked through the existing `execute_analysis_run` service in an isolated in-memory SQLite database. Missing T7/T8 dependencies cause the run to fail explicitly.
- T7 source coverage currently uses normalized Event `source` values. Several CSV evidence families share `source=log`; family-specific scheduler/auth coverage may therefore not be distinguishable without a change outside T9/T10.
- Ground truth is authored by the simulator independently of intelligence output. Scoring uses event artifact references, not generated claim IDs.

## Reproducibility

Run `make bench`. Use `python3 bench/run.py --seed 123` to override scenario seeds. Results are written to `bench/results/results.json`, `bench/results/results.csv`, and this report. Generated benchmark records are deterministic for the same YAML and seed; run IDs and execution timestamps are intentionally omitted from result artifacts.
