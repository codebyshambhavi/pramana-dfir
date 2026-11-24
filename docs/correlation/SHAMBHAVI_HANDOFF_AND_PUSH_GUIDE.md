# Shambhavi — Correlation Engine Handoff / Pull Request Guide

## Scope
This snapshot contains Shambhavi's Role 1 correlation-engine implementation:
- Stage 2: versioned 45-parameter registry (44 enabled, 1 disabled), vocabulary and registry validation.
- Stage 3: canonical field resolution, validated primary anchors and indexed candidate generation.
- Stage 4: registry-driven feature evaluation, normalisation, reliability, missing-value policies, collision/contradiction penalties and secondary scoring.
- Stage 5: deterministic orchestration, `CorrelationResult`, relationship IDs, evidence pointers and explanations.
- Stage 6 boundary: case-scoped service and registry-description API surface, plus JSON Schema contract.
- Stage 7: labelled-pair evaluator. This is an evaluation framework, not evidence of real-world performance.
- Stage 8: documentation and test records.

## Verification reproduced in this environment
Command: `python -m compileall -q intelligence/correlation && pytest -q intelligence`
Result: **625 passed**.

Previously recorded broader suite: `342 passed, 8 failed, 11 skipped, 10 errors`. See `docs/correlation/STAGE_5_8_IMPLEMENTATION.md`. Issues include missing Scapy/ImageHash dependencies and a stale migration expectation. Do not describe the full repository suite as green.

## Completed Shambhavi-owned implementation
Public service entry points:
- `intelligence.correlation.correlate_relationships(...)`
- `intelligence.correlation.correlate_case_events(...)`
- `intelligence.correlation.registry_description(...)`
- `intelligence.correlation.evaluate_labelled_pairs(...)`

The service is ready for backend consumption. The shared response schema is `contracts/relationship.schema.json`.

## Cross-team integration still requiring owners
1. **Saiesha:** approve the shared Relationship persistence model, case authorization dependency, run binding and immutable snapshot semantics. The backend router does not yet persist this Relationship object. After agreement, register `GET /correlation/registry` and case-scoped `GET /cases/{case_id}/relationships`. Historical relationships must be read from persisted run snapshots, never recomputed using the current registry.
2. **Niharika:** verify the T7/T8 consumer mapping against the relationship contract. Do not rewrite T7/T8.
3. **Anupriya/team:** provide approved, source-traceable labelled event pairs. Run development and held-out evaluation only on those data. Do not present synthetic unit fixtures as a real benchmark.
4. Re-run full regression when Scapy and ImageHash are available; resolve the stale migration expectation with its owner.

## Push procedure
This ZIP is a source snapshot and does not contain the original Git history or remote configuration. Do not push it as a new repository.
1. Clone the team's actual GitHub repository.
2. Create a branch: `git switch -c feature/shambhavi-correlation-engine`
3. Copy the correlation additions from this snapshot into that clone, preserving existing files.
4. Review `backend/app/routers/evidence.py`: it contains a one-line shared import fix and must retain CRLF line endings. Do not replace it with a line-ending-normalized copy.
5. Run `python -m compileall -q intelligence/correlation` and `pytest -q intelligence`.
6. Review `git status --short`, `git diff --check`, and `git diff --stat`.
7. Commit and push:
   - `git add intelligence/correlation intelligence/tests/test_correlation_registry.py intelligence/tests/test_correlation_engine_stage3_4.py intelligence/tests/test_correlation_orchestration_stage5.py intelligence/tests/test_correlation_service_evaluation_stage6_7.py contracts/relationship.schema.json docs/correlation`
   - Stage `backend/app/routers/evidence.py` only if the team confirms that the shared fix belongs in this PR.
   - `git commit -m "Implement explainable correlation engine"`
   - `git push -u origin feature/shambhavi-correlation-engine`
8. Open a PR and request review from Saiesha and Niharika for shared interfaces.

## Do not claim
- No real-world precision/recall or calibrated thresholds until approved labelled data has been evaluated.
- No backend route/persistence integration until implemented and reviewed.
- No T7/T8 integration verification until Niharika confirms it.
- No claim that all repository tests pass; report only commands actually run.
