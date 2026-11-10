# PRAMANA Synthetic Benchmark Report

Controlled synthetic evidence only; these results are not real-world accuracy claims.

- Scenarios evaluated: 8
- Events evaluated: 1520
- Development scenarios: 3
- Held-out scenarios: 5
- Reproducibility: scenario YAML seeds; use `make bench` or `python3 bench/run.py --seed N`.
- `make bench` does not run tests. Run `python -m pytest bench/tests` separately; test results are intentionally not embedded in generated benchmark reports.

## Results by split

### dev

#### B1 — 3 scenarios, 420 events

| Metric | Raw count (numerator / denominator) | Percentage |
|---|---:|---:|
| Link precision (strict artifact references) | 4 / 1439 | 0.28% |
| Link recall (strict artifact references) | 4 / 10 | 40.00% |
| Link precision (duplicate-equivalence aware) | 4 / 1382 | 0.29% |
| Link recall (duplicate-equivalence aware) | 4 / 10 | 40.00% |
| Decoy false-positive rate | 3 / 3 | 100.00% |
| Top-hypothesis accuracy (includes correct UNDETERMINED) | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Correct UNDETERMINED rate | 0 / 0 (ground truth does not expect an undetermined outcome; system did not produce a top-hypothesis prediction) | N/A |
| Over-claim rate | 0 / 0 (ground truth does not expect an undetermined outcome; system did not produce a top-hypothesis prediction) | N/A |
| Selective accuracy (correct commitments / commitments) | 0 / 0 (system made no hypothesis commitments (abstained or produced no prediction)) | N/A |
| Abstention rate (UNDETERMINED on definite ground truth) | 0 / 0 (no definite ground-truth hypothesis with a system prediction) | N/A |
| Contradiction recall | 0 / 0 (system did not produce contradiction predictions) | N/A |
| MISSING vs UNOBSERVABLE accuracy | 0 / 0 (system did not produce absence classifications) | N/A |
| Claim lineage resolution | 0 / 0 (system did not expose claim lineage counts) | N/A |
| Tamper invalidation accuracy (strict artifact references) | 0 / 0 (system did not produce tamper invalidation predictions) | N/A |
| Tamper invalidation accuracy (duplicate-equivalence aware) | 0 / 0 (system did not produce tamper invalidation predictions) | N/A |

#### B2 — 3 scenarios, 420 events

| Metric | Raw count (numerator / denominator) | Percentage |
|---|---:|---:|
| Link precision (strict artifact references) | 4 / 1439 | 0.28% |
| Link recall (strict artifact references) | 4 / 10 | 40.00% |
| Link precision (duplicate-equivalence aware) | 4 / 1382 | 0.29% |
| Link recall (duplicate-equivalence aware) | 4 / 10 | 40.00% |
| Decoy false-positive rate | 3 / 3 | 100.00% |
| Top-hypothesis accuracy (includes correct UNDETERMINED) | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Correct UNDETERMINED rate | 0 / 0 (ground truth does not expect an undetermined outcome; system did not produce a top-hypothesis prediction) | N/A |
| Over-claim rate | 0 / 0 (ground truth does not expect an undetermined outcome; system did not produce a top-hypothesis prediction) | N/A |
| Selective accuracy (correct commitments / commitments) | 0 / 0 (system made no hypothesis commitments (abstained or produced no prediction)) | N/A |
| Abstention rate (UNDETERMINED on definite ground truth) | 0 / 0 (no definite ground-truth hypothesis with a system prediction) | N/A |
| Contradiction recall | 0 / 0 (system did not produce contradiction predictions) | N/A |
| MISSING vs UNOBSERVABLE accuracy | 0 / 0 (system did not produce absence classifications) | N/A |
| Claim lineage resolution | 0 / 0 (system did not expose claim lineage counts) | N/A |
| Tamper invalidation accuracy (strict artifact references) | 0 / 0 (system did not produce tamper invalidation predictions) | N/A |
| Tamper invalidation accuracy (duplicate-equivalence aware) | 0 / 0 (system did not produce tamper invalidation predictions) | N/A |

#### PRAMANA — 3 scenarios, 420 events

| Metric | Raw count (numerator / denominator) | Percentage |
|---|---:|---:|
| Link precision (strict artifact references) | 3 / 6 | 50.00% |
| Link recall (strict artifact references) | 3 / 10 | 30.00% |
| Link precision (duplicate-equivalence aware) | 3 / 3 | 100.00% |
| Link recall (duplicate-equivalence aware) | 3 / 10 | 30.00% |
| Decoy false-positive rate | 0 / 3 | 0.00% |
| Top-hypothesis accuracy (includes correct UNDETERMINED) | 1 / 3 | 33.33% |
| Correct UNDETERMINED rate | 1 / 1 | 100.00% |
| Over-claim rate | 0 / 1 | 0.00% |
| Selective accuracy (correct commitments / commitments) | 0 / 1 | 0.00% |
| Abstention rate (UNDETERMINED on definite ground truth) | 1 / 2 | 50.00% |
| Contradiction recall | 0 / 6 | 0.00% |
| MISSING vs UNOBSERVABLE accuracy | 1 / 3 | 33.33% |
| Claim lineage resolution | 429 / 429 | 100.00% |
| Tamper invalidation accuracy (strict artifact references) | 0 / 3 | 0.00% |
| Tamper invalidation accuracy (duplicate-equivalence aware) | 3 / 3 | 100.00% |

### held-out

#### B1 — 5 scenarios, 1100 events

| Metric | Raw count (numerator / denominator) | Percentage |
|---|---:|---:|
| Link precision (strict artifact references) | 7 / 6405 | 0.11% |
| Link recall (strict artifact references) | 7 / 18 | 38.89% |
| Link precision (duplicate-equivalence aware) | 7 / 6181 | 0.11% |
| Link recall (duplicate-equivalence aware) | 7 / 18 | 38.89% |
| Decoy false-positive rate | 34 / 34 | 100.00% |
| Top-hypothesis accuracy (includes correct UNDETERMINED) | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Correct UNDETERMINED rate | 0 / 0 (ground truth does not expect an undetermined outcome; system did not produce a top-hypothesis prediction) | N/A |
| Over-claim rate | 0 / 0 (ground truth does not expect an undetermined outcome; system did not produce a top-hypothesis prediction) | N/A |
| Selective accuracy (correct commitments / commitments) | 0 / 0 (system made no hypothesis commitments (abstained or produced no prediction)) | N/A |
| Abstention rate (UNDETERMINED on definite ground truth) | 0 / 0 (no definite ground-truth hypothesis with a system prediction) | N/A |
| Contradiction recall | 0 / 0 (system did not produce contradiction predictions) | N/A |
| MISSING vs UNOBSERVABLE accuracy | 0 / 0 (system did not produce absence classifications) | N/A |
| Claim lineage resolution | 0 / 0 (system did not expose claim lineage counts) | N/A |
| Tamper invalidation accuracy (strict artifact references) | 0 / 0 (system did not produce tamper invalidation predictions) | N/A |
| Tamper invalidation accuracy (duplicate-equivalence aware) | 0 / 0 (system did not produce tamper invalidation predictions) | N/A |

#### B2 — 5 scenarios, 1100 events

| Metric | Raw count (numerator / denominator) | Percentage |
|---|---:|---:|
| Link precision (strict artifact references) | 7 / 6405 | 0.11% |
| Link recall (strict artifact references) | 7 / 18 | 38.89% |
| Link precision (duplicate-equivalence aware) | 7 / 6181 | 0.11% |
| Link recall (duplicate-equivalence aware) | 7 / 18 | 38.89% |
| Decoy false-positive rate | 34 / 34 | 100.00% |
| Top-hypothesis accuracy (includes correct UNDETERMINED) | 0 / 0 (system did not produce a top-hypothesis prediction) | N/A |
| Correct UNDETERMINED rate | 0 / 0 (ground truth does not expect an undetermined outcome; system did not produce a top-hypothesis prediction) | N/A |
| Over-claim rate | 0 / 0 (ground truth does not expect an undetermined outcome; system did not produce a top-hypothesis prediction) | N/A |
| Selective accuracy (correct commitments / commitments) | 0 / 0 (system made no hypothesis commitments (abstained or produced no prediction)) | N/A |
| Abstention rate (UNDETERMINED on definite ground truth) | 0 / 0 (no definite ground-truth hypothesis with a system prediction) | N/A |
| Contradiction recall | 0 / 0 (system did not produce contradiction predictions) | N/A |
| MISSING vs UNOBSERVABLE accuracy | 0 / 0 (system did not produce absence classifications) | N/A |
| Claim lineage resolution | 0 / 0 (system did not expose claim lineage counts) | N/A |
| Tamper invalidation accuracy (strict artifact references) | 0 / 0 (system did not produce tamper invalidation predictions) | N/A |
| Tamper invalidation accuracy (duplicate-equivalence aware) | 0 / 0 (system did not produce tamper invalidation predictions) | N/A |

#### PRAMANA — 5 scenarios, 1100 events

| Metric | Raw count (numerator / denominator) | Percentage |
|---|---:|---:|
| Link precision (strict artifact references) | 5 / 10 | 50.00% |
| Link recall (strict artifact references) | 5 / 18 | 27.78% |
| Link precision (duplicate-equivalence aware) | 5 / 5 | 100.00% |
| Link recall (duplicate-equivalence aware) | 5 / 18 | 27.78% |
| Decoy false-positive rate | 0 / 34 | 0.00% |
| Top-hypothesis accuracy (includes correct UNDETERMINED) | 2 / 5 | 40.00% |
| Correct UNDETERMINED rate | 1 / 1 | 100.00% |
| Over-claim rate | 0 / 1 | 0.00% |
| Selective accuracy (correct commitments / commitments) | 1 / 1 | 100.00% |
| Abstention rate (UNDETERMINED on definite ground truth) | 3 / 4 | 75.00% |
| Contradiction recall | 0 / 10 | 0.00% |
| MISSING vs UNOBSERVABLE accuracy | 1 / 5 | 20.00% |
| Claim lineage resolution | 1116 / 1116 | 100.00% |
| Tamper invalidation accuracy (strict artifact references) | 0 / 5 | 0.00% |
| Tamper invalidation accuracy (duplicate-equivalence aware) | 5 / 5 | 100.00% |

## Metric interpretation

- Strict link and tamper metrics compare exact artifact references. Equivalence-aware variants additionally normalize duplicate rows using the simulator's explicit `duplicate_rows` original-to-duplicate mapping; they are reported alongside, never instead of, strict scores.
- Selective accuracy scores only non-UNDETERMINED commitments against defined ground truth. Abstention rate separately measures UNDETERMINED outputs on cases with a definite ground-truth hypothesis.

## Known limitations

- The scenarios are controlled synthetic fixtures and do not establish real-world forensic accuracy.
- B1/B2 only predict event links; they do not produce hypothesis, contradiction, absence, lineage, or tamper predictions. Those metrics are reported as unavailable where no output exists.
- The main scenario runner exercises T4 verification and T8 run-diff services directly on disposable generated evidence. The separate ROLE 2 integration test also exercises the public demo tamper endpoint, verification quarantine, Run A invalidation, and child-run diff through the API.
- The T8 runner is database-backed and is invoked through the existing `execute_analysis_run` service in an isolated in-memory SQLite database. Missing T7/T8 dependencies cause the run to fail explicitly.
- T7 source coverage currently uses normalized Event `source` values. Several CSV evidence families share `source=log`; family-specific scheduler/auth coverage may therefore not be distinguishable without a change outside T9/T10.
- Ground truth is authored by the simulator independently of intelligence output. Scoring uses event artifact references, not generated claim IDs.

## Reproducibility

Run `make bench`. Use `python3 bench/run.py --seed 123` to override scenario seeds. Results are written to `bench/results/results.json`, `bench/results/results.csv`, and this report. Generated benchmark records are deterministic for the same YAML and seed; run IDs and execution timestamps are intentionally omitted from result artifacts.
