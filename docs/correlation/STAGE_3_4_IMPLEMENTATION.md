# PRAMANA Correlation Engine — Stage 3 and Stage 4

**Scope:** Shambhavi / Role 1 — field resolution, primary anchors, indexed candidate generation, registry-driven feature evaluation, reliability and secondary scoring.

**Registry:** `corr-registry-v1`  
**Configuration:** `corr-config-v1`  
**Calibration:** PROVISIONAL. No real-world accuracy claim is made.

## Stage 3 — field resolution, anchors and candidate generation

### `fields.py`

`resolve_field(event, field_name, ...)` returns a `ResolvedField` containing the canonical value, a `PRESENT` / `MISSING` / `INVALID` status, and a source locator. `resolve_event` resolves the closed vocabulary from `vocabulary.py`.

The resolver reuses the existing `intelligence.entities` normalisers and `extract_content_hash`. It handles Gmail, Outlook/PST-compatible mail shapes, Zeek dotted-key fields, PCAP endpoints and ports, source-clock uncertainty, parser confidence, acquisition method and evidence integrity. Placeholder strings are treated as missing. Invalid IPs/ports/timestamps are not converted into matchable values. Actor usernames do not treat IP literals as usernames.

Evidence integrity is resolved from the event's explicit `integrity_status`, or from the optional `evidence_context` map keyed by evidence ID. `ACTIVE` with no verification result becomes `UNVERIFIED`; `QUARANTINED`, `REMOVED`, `MISMATCH`, `MISSING` and `CUSTODY_BROKEN` remain distinguishable.

### `anchors.py`

`evaluate_anchor` and `evaluate_anchors` evaluate only registry parameters with role `ANCHOR`. Supported anchor types are validated SHA-256, exact message identifiers, explicit message references, scoped thread IDs and scoped network session IDs.

Anchor values are not returned in plaintext: the result carries a short SHA-256 reference. Each result includes its parameter/anchor type, validation status, source event IDs, evidence references and explanation. Missing or blocked evidence integrity rejects a direct anchor. Thread anchors require matching account/source scope; session anchors use the configured first-present capture/evidence scope.

Filename, IP and timestamp similarity are never anchors. In particular, this engine's PRIMARY SHA-256 relationship is separate from T6 `SAME_OBJECT_FLOW` claim promotion; T6's independent compatible-sequence rule remains unchanged.

### Indexed candidate generation

`generate_candidate_pairs` builds buckets from the registry's configured indexes, applies the registry `max_bucket_size`, records skipped buckets using hashed bucket values, and adds a bounded time-window index using a sorted sliding window. It enforces case equality and returns deterministic pair order. Candidate generation is only a comparison optimisation; it is not a relationship decision.

## Stage 4 — feature evaluation and scoring

### `features.py`

`evaluate_parameter` and `evaluate_features` implement the registry extraction methods for exact matches, set overlap/containment, token Jaccard, time separation, uncertainty-driven interval overlap, ordered actions, alias groups, endpoint pairs, conflict checks, identity conflicts and reliability-factor methods.

Every signal reports its parameter ID, role, evaluation status, normalised value and details. Missing inputs are represented as `UNAVAILABLE`, not as a mismatch. Reliability factors apply their registry missing-value policies. Pair reliability uses the feature's configured `MIN` or `PRODUCT` combination.

`COMMON_VALUE` collision semantics preserve the raw signal, compute the clean signal without common values, and apply the configured penalty factor. `HUB_COUNT` uses the existing T5 `_hub_factor` formula and the registry's hub thresholds.

### `scorer.py`

`score_pair(a, b, registry, ...)` returns a deterministic score record containing:

- bounded score and raw score;
- threshold classification (`HIGH_CONFIDENCE`, `ANALYST_REVIEW`, `BELOW_THRESHOLD`);
- per-feature contribution and reliability;
- separate collision-penalty lines;
- contradiction counter-signals;
- unavailable/blocked parameter lists;
- reliability-factor results;
- registry version, registry hash, config version and calibration status.

The score follows the registry formula: weighted feature contribution multiplied by reliability, less collision and contradiction penalties, clamped to the configured score range. The registry thresholds remain provisional.

## Tests and verification

`intelligence/tests/test_correlation_engine_stage3_4.py` covers field normalisation and provenance, Zeek/PCAP extraction, anchor validation and scope, filename/IP/time non-anchor behaviour, case-scoped indexed candidates, max-bucket reporting, scoring determinism, collision accounting and threshold sanity checks.

It also executes **all 90 positive/negative registry fixtures** against the real resolver/evaluator. This prevents the registry fixture examples from remaining documentation-only.

Verification executed in the implementation environment:

```text
python -m compileall -q intelligence/correlation
pytest -q intelligence
610 passed
```

The 610 count includes the 310 original intelligence tests, 194 Stage 2 registry tests, and 106 Stage 3/4 tests (including the 90 registry fixture executions). No test was removed or weakened.

## Deliberate boundary / not yet implemented

This delivery stops at Stage 4. It does **not** yet implement the Stage 5 orchestration result (`CorrelationResult` / `correlate_relationships`), explanation service module, API routes, persistence, benchmark evaluation, T7/T8 adapter, or final end-to-end report integration. Those remain later stages and should consume these modules rather than reimplementing their logic.

The caller must supply `source_clocks` as a mapping of source names to `SourceClock` objects, and may supply `evidence_context` for evidence status/verification data. The existing timeline module's environment parser does not yet recognise all mail/Zeek sources; this module deliberately accepts the mapping directly without changing T2/T5/T6.
