# PRAMANA Correlation Engine — Stages 5–8 implementation record

Date: 2026-11-24  
Owner: Shambhavi — Role 1, Correlation Engine and Explainability

## Stage 5 — Explainability and orchestration

Implemented:

- `intelligence/correlation/explain.py`: deterministic summaries derived from anchor and score accounting. It does not call an LLM.
- `intelligence/correlation/orchestration.py`: `correlate_relationships(events, registry, source_clocks=None, evidence_context=None)` and immutable `CorrelationResult` wrapper.
- Deterministic `rel_<sha256>` IDs; stable ordering; source/target event and case IDs; evidence pointers; anchor data; feature contributions; counter-signals; unavailable/blocked parameter lists; score; thresholds; registry/config version and registry hash.
- Missing `case_id`, missing `event_id`, missing source and duplicate event IDs within a case are rejected.
- Mixed-case input is permitted, but pairs and collision/hub calculations are strictly case-scoped.
- A validated PRIMARY anchor is emitted separately and is not duplicated as a SECONDARY result. T6 flow-claim promotion/sequence rules are not modified.
- Secondary results are emitted only at or above `T_REVIEW`; `T_HIGH` distinguishes `HIGH_CONFIDENCE` from `ANALYST_REVIEW`.

## Stage 6 — service and API boundary

Implemented:

- `intelligence/correlation/service.py`: `correlate_case_events()` enforces one requested case and delegates to the orchestrator.
- `registry_description()` exposes the authoritative `Registry.describe()` payload for a future read-only `GET /correlation/registry` route.
- `contracts/relationship.schema.json`: shared response contract for correlation relationships.

Intentionally not implemented: backend router registration, `GET /cases/{case_id}/relationships`, database persistence, migrations or auth changes. The current repository has no approved shared Relationship persistence model, and case workflow/database ownership belongs to Saiesha. Creating a parallel table or bypassing the case authorization dependency would be unsafe. The backend owner should add the registry endpoint and persisted relationship endpoint using this service/contract after the shared model and run-snapshot contract are agreed.

Suggested API boundary:

- `GET /correlation/registry` → `registry_description(load_registry())`.
- `GET /cases/{case_id}/relationships` → load only persisted relationships for the authorised case and its immutable analysis run; do not recompute historical results from the current registry.

## Stage 7 — evaluation

Implemented `intelligence/correlation/evaluate.py` with `evaluate_labelled_pairs()`:

- Accepts explicitly labelled same-case event pairs and a declared `development` or `held_out` split.
- Uses validated anchors first; otherwise uses the configured review threshold.
- Reports TP, FP, TN, FN, precision, recall, false-positive rate, false-negative rate, F1 and per-expected-relationship-type counts.
- Rejects duplicate labelled pairs, cross-case pairs, malformed labels and unspecified split names.
- Does not fit weights, tune thresholds or fabricate data.

No representative labelled correlation-pair dataset was supplied in the repository handoff. Therefore no performance/accuracy claim is made. The evaluator was verified with a small synthetic unit-test fixture only; those test values are not benchmark results and must not be presented as real-world accuracy.

## Stage 8 — regression and verification

Executed in this environment:

- `python -m compileall -q intelligence/correlation` — passed.
- `pytest -q intelligence` — **625 passed**.
- Targeted correlation suites — **121 passed**.
- Broader command `pytest -q bench tests/integration evidence-engine/tests backend/tests` — **342 passed, 8 failed, 11 skipped, 10 errors**.

Broader-suite limitations/failures observed:

- Integration tests error because Scapy is not installed; PCAP parser explicitly requires it.
- Evidence-engine tests fail because ImageHash is not installed; image parser explicitly requires it.
- Backend sample-case API test errors because Scapy is unavailable.
- `backend/tests/test_t3_migrate.py::test_migrate_pre_t3_adds_columns_tables_and_guards` fails on an expectation mismatch: the migrator additionally reports seven `cases.*` columns. This is outside the correlation work and was not modified.
- No dependency installation was attempted and no unrelated test was weakened.

## Important case-isolation correction

Candidate index buckets are now keyed by `(case_id, index, value)`, so common identifiers in another case cannot inflate a bucket and suppress valid same-case candidates. Hub/collision scoring receives only events from the pair's case. This is required to prevent cross-case effects, not merely cross-case output edges.

## Remaining integration actions for the team

1. Saiesha: approve a shared Relationship model/schema, run binding, case authorization and immutable persistence contract; then register the API routes.
2. Niharika: consume the returned relationship records in T7/T8 only after the shared contract is agreed; no T7/T8 source was modified here.
3. Anupriya: provide representative, consented, source-traceable labelled event-pair data and confirm parser provenance fields for calibration/evaluation.
4. Shambhavi: run the evaluator on approved development and held-out labelled sets, review false positives/negatives, and only then propose calibrated weights/thresholds.

## Reproducibility

The registry hash is embedded in each relationship. Relationship IDs are deterministic for the same pair, score accounting and registry version. Historical relationships must be persisted with their original registry hash/config version; never recompute them using a newer registry during report or run replay.
