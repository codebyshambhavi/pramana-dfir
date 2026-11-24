# PRAMANA Role 4 Handover: T7/T8 Continuity, Compatibility Integration & Verification

**Owner:** Niharika Singh  
**Role:** Role 4 — T7/T8 Continuity, Compatibility Integration & Verification  
**Branch:** `feature/niharika-t7-t8-integration-verification`  
**Target Branch:** `main` (baseline commit `d4592be`)

---

## 1. Executive Summary

This handover documents the integration and continuity hardening of PRAMANA's **T7 Hypothesis Evaluation Engine** (`intelligence/hyp/engine.py`), **T8 Narrative Reconstruction Engine** (`intelligence/hyp/reconstruct.py`), and **Immutable Analysis-Run Service** (`backend/app/services/runs.py`) with the updated PRAMANA multi-source evidence acquisition and versioned correlation architecture.

All existing T7, T8, and immutable analysis-run capabilities have been preserved without breaking changes, while adding first-class support for:
1. Consuming versioned `PRIMARY` and `SECONDARY` correlation relationships from Shambhavi's correlation engine (`intelligence/correlation/`).
2. Consuming normalised multi-source events (Gmail, Outlook, PST, PCAP, Zeek, system/auth/browser/chat logs) with structured source locators from Anupriya's evidence engine (`evidence-engine/`).
3. Enriching immutable analysis-run manifests and snapshots with all 10 required continuity fields (`run_id`, `case_id`, `input_evidence_hashes`, `parser_versions`, `correlation_config_version`, `module_versions`, `started_at`, `completed_at`, `status`, `output_manifest_hash`) consumed by Saiesha's case workflow and immutable PDF reporting (`backend/app/reports/run_report.py`).

---

## 2. Scope of Niharika's Assignment

As defined in Section 7.4 and Section 13 of the post-mentorship engineering plan, Niharika's assignment is a **bounded continuity and integration assignment**:
- **In Scope:**
  - Verify and preserve existing T7, T8, and immutable analysis-run tests.
  - Adapt T7 (`intelligence/hyp/engine.py`) to consume the updated relationship contract (`PRIMARY` vs `SECONDARY`, feature contributions, counter-signals, evidence references, and explanations) while preserving disconfirmation-based ranking and `UNDETERMINED` abstention.
  - Adapt T8 (`intelligence/hyp/reconstruct.py`) to consume normalised multi-source events, preserve source locators (`Message-ID`, PST folder/item ID, PCAP packet/frame number, Zeek UID, log line/offset), preserve raw and UTC timestamps, surface chronology uncertainty and contradictions, and attach relationship and hypothesis references.
  - Ensure immutable analysis runs record all required provenance/version/hash metadata and bind T7 and T8 outputs explicitly to `analysis_run_id`.
  - Add unit, compatibility, and focused end-to-end integration tests.
- **Out of Scope (Respecting Teammate Boundaries):**
  - Does not rebuild T7 or T8 from scratch or replace the interval-based reconstruction algorithm.
  - Does not create a second correlation engine (consumes Shambhavi's `intelligence/correlation`).
  - Does not re-implement Gmail/Outlook/PST/PCAP/Zeek acquisition (consumes Anupriya's `evidence-engine` outputs).
  - Does not modify Saiesha's case workflow or PDF report renderer (`backend/app/reports/run_report.py`).

---

## 3. Baseline Test Status Before Changes

Before any code modifications were made on `origin/main` (`d4592be`):

| Metric | Count | Notes |
|---|---:|---|
| **Collected** | `1,027` | Full repository pytest collection (`backend`, `bench`, `evidence-engine`, `intelligence`, `tests/integration`) |
| **Passed** | `1,018` | All existing unit, integration, and benchmark integrity tests passed |
| **Skipped** | `9` | `backend/tests/test_postgres_migration.py` (skipped when `PRAMANA_TEST_PG_URL` is not set; requires disposable PostgreSQL >= 14) |
| **Failed** | `0` | Clean baseline |

---

## 4. Files Modified and Created

### Modified Files
- `intelligence/timeline.py` — Extended `KNOWN_SOURCES` to include `"gmail"`, `"outlook"`, `"pst"`, and `"zeek"` alongside `"browser"`, `"chat"`, `"log"`, `"pcap"`, and `"image"` so source-clock uncertainty rules cover all Event v1.1 sources.
- `intelligence/hyp/engine.py` — Added `normalize_event_contract`, `validate_relationship_payload`, and `adapt_relationships_for_hypotheses`; extended `ItemEvaluation`, `RankedHypothesis`, `HypothesisEvaluationResult`, and `evaluate_hypotheses` to consume `PRIMARY` and `SECONDARY` relationships, track supporting/contradicting relationship/evidence/event IDs, enforce case isolation, and preserve `analysis_run_id` and `conclusion_type="MACHINE_HYPOTHESIS"`.
- `intelligence/hyp/reconstruct.py` — Added `extract_source_locator_details` and `normalize_event_for_reconstruction`; extended `StageReconstruction`, `NarrativeReconstruction`, and `reconstruct_narrative` to preserve normalised event fields, structured source locators across all 5 forensic source categories, relationship links, missing/conflicting timestamps, chronology uncertainty, contradictions, duplicate event handling, case isolation, and `analysis_run_id`.
- `intelligence/hyp/__init__.py` — Exported the new T7/T8 compatibility helpers (`adapt_relationships_for_hypotheses`, `extract_source_locator_details`, `normalize_event_contract`, `normalize_event_for_reconstruction`, `validate_relationship_payload`).
- `backend/app/services/runs.py` — Added `build_module_versions` and `compute_output_manifest_hash`; updated `execute_analysis_run`, `get_run_details`, and `verify_run_reproducibility` to record and return all 10 required Phase 4 immutable analysis-run manifest fields, consume correlation relationships, and verify historical replay with relationships.
- `bench/run.py` — Updated `_stable_output` to strip `"analysis_run_id"` alongside `"run_id"` and `"created_at"` when canonicalizing run-instance metadata in benchmark reconstruction comparisons.

### Created Files
- `intelligence/tests/test_t7_relationship_compatibility.py` — 18 unit and compatibility tests for Phase 2 (T7 relationship contract consumption, `PRIMARY` vs `SECONDARY` distinction, supporting/contradicting references, missing evidence neutrality, invalid payload rejection, determinism, and case isolation).
- `intelligence/tests/test_t8_event_relationship_compatibility.py` — 7 compatibility tests for Phase 3 (normalised event ingestion, source-locator traceability across Gmail/Outlook/PST/PCAP/Zeek/logs, relationship-linked reconstruction, missing/conflicting timestamps, chronology uncertainty, contradictions, duplicate handling, determinism, and case isolation).
- `backend/tests/test_t7_t8_integration_continuity.py` — 3 integration tests for Phases 4, 5, and 6 (immutable analysis-run manifest fields, write-once immutability, deterministic reproducibility, and full end-to-end pipeline `Evidence -> Normalised Events -> Relationships -> T7 Hypotheses -> T8 Reconstruction -> Immutable Analysis Run -> PDF Report`).
- `docs/NIHARIKA_T7_T8_INTEGRATION_HANDOVER.md` — This engineering handover document.

---

## 5. T7 Hypothesis Engine Compatibility Design

`intelligence/hyp/engine.py` preserves its deterministic disconfirmation-based evaluation model while adding a strict contract validation and adaptation layer (`validate_relationship_payload` and `adapt_relationships_for_hypotheses`):

1. **Dual Relationship Contract Support:** Accepts both the Section 5.6 relationship contract (`threshold_version`, `evidence_refs`, `review_status`, `config_version`) and Shambhavi's Stage 5 `CorrelationResult` payloads (`thresholds`, `evidence_pointers`, `status`, `registry_version`).
2. **Primary vs Secondary Distinction:**
   - `PRIMARY` relationships represent direct validated anchors (e.g., exact RFC `Message-ID`, exact content/attachment SHA-256, exact Zeek `uid`). When non-rejected, they derive corroborated/asserted `SAME_OBJECT_FLOW` and (when actor/device is present) `ACTOR_DEVICE_CONSISTENT` evidence inputs while retaining `relationship_id`, `relationship_type="PRIMARY"`, and `evidence_refs`.
   - `SECONDARY` relationships represent weighted contextual/probabilistic associations (`0.0 <= score <= 1.0`). They **never** derive `SAME_OBJECT_FLOW` claims (preventing a high secondary score from auto-confirming data transfer or exfiltration) and are capped at Grade `C` contextual support (`ACTOR_DEVICE_CONSISTENT`) only when above threshold and free of counter-signals.
3. **Counter-Signals & Contradictions:** Relationships carrying `counter_signals` derive explicit contradiction inputs (`SESSION_ORIGIN_MISMATCH`, `LOCATION_CONFLICT`) with `CONTRADICTS` edges, populating `contradicting_relationship_ids`, `contradicting_evidence_ids`, and `contradicting_event_ids` on affected hypotheses.
4. **Machine Hypothesis vs Investigator Conclusion:** Every `RankedHypothesis` carries `conclusion_type="MACHINE_HYPOTHESIS"` and `investigator_confirmed=False`, ensuring machine-ranked hypotheses are never presented as investigator-confirmed forensic conclusions.

---

## 6. T8 Reconstruction Engine Compatibility Design

`intelligence/hyp/reconstruct.py` normalizes every ingested event through `normalize_event_for_reconstruction` and `extract_source_locator_details`:

1. **Bidirectional Field Mapping:** Transparently bridges Section 5.6 normalised event fields (`event_type`, `event_time_utc`, `raw_timestamp`, `source_locator`, `extraction_quality`) and Event v1.1 fields (`action`, `timestamp`, `artifact_ref`, `raw`).
2. **Structured Source Locator Extraction:** Extracts and preserves source-specific forensic locators in `source_locator_details`:
   - **Gmail / Outlook:** `message_id` (RFC 5322 `Message-ID` / `internetMessageId`)
   - **PST:** `pst_folder_path`, `pst_item_id`, and `message_id`
   - **PCAP:** `packet_number` (packet/frame index)
   - **Zeek:** `zeek_uid` and `line_number`
   - **Logs:** `line_number`, `byte_offset`, and `log_line_offset`
3. **Chronology Uncertainty & Contradiction Tracking:**
   - Computes effective UTC time intervals (`TimeInterval`) using source-clock offset and uncertainty bounds.
   - Surfaces missing timestamps (`missing_timestamp_event_ids`, `missing_timestamp_events`) without fabricating timestamps.
   - Detects discrepancies between explicit `raw_timestamp` and `event_time_utc` (`conflicting_timestamp_events`, `discrepancy_seconds`), duplicate `event_id`s with conflicting timestamps, and shared source locators with conflicting timestamps.
   - Records stage-level ordering anomalies (`OUT_OF_ORDER`, `CONCURRENT_OR_OVERLAPPING`) in `chronology_uncertainties` and `contradictions`.

---

## 7. Immutable Analysis-Run Manifest and Reproducibility Design

`backend/app/services/runs.py` preserves the write-once SQL schema of `AnalysisRun` and `RunSnapshot` while recording all 10 required Phase 4 continuity fields in the run response, `get_run_details`, and the immutable `RunSnapshot`:

- `run_id` (and alias `analysis_run_id`)
- `case_id`
- `input_evidence_hashes` (sorted list of `{"evidence_id", "sha256"}` for all active evidence in the run)
- `parser_versions` (`{"known": [...], "unknown_evidence_ids": [...]}`)
- `correlation_config_version` (from the active correlation registry or explicit override)
- `module_versions` (`engine`, `t5_link_engine`, `correlation_engine`, `t6_claims_engine`, `t7_hypothesis_engine`, `t8_reconstruction_engine`, `t8_immutable_runs`)
- `started_at` (ISO-8601 UTC timestamp)
- `completed_at` (ISO-8601 UTC timestamp)
- `status` (`"COMPLETED"`)
- `output_manifest_hash` (deterministic SHA-256 over canonical run inputs, versions, `assumptions_hash`, `template_hash`, `ranking_hash`, `outcome`, `claim_ids`, `relationship_ids`, and `h0_unassigned_event_ids`)

Both `AnalysisRun` and `RunSnapshot` remain protected by SQLAlchemy `before_flush` and `do_orm_execute` write-once guards (`ImmutableRecordError`).

---

## 8. Relationship Input Contract Consumed by T7/T8

`validate_relationship_payload` validates the following contract:
- `relationship_id` (`str`, non-empty)
- `case_id` (`str`, non-empty, must match active case)
- `source_event_id` (`str`, non-empty, distinct from `target_event_id`)
- `target_event_id` (`str`, non-empty)
- `relationship_type` (`"PRIMARY"` or `"SECONDARY"`)
- `score` (`float | None` in `[0.0, 1.0]`; required numeric for `SECONDARY`, optional/null for `PRIMARY`)
- `threshold_version` (`str`, extracted from `threshold_version`, `thresholds`, or `registry_version`)
- `feature_contributions` (`list[dict]`, each containing `parameter_id`)
- `counter_signals` (`list[dict]`)
- `explanation` (`str`, non-empty human-readable explanation)
- `evidence_refs` (`list[str]`, extracted from `evidence_refs` or `evidence_pointers`)
- `review_status` (`str`, extracted from `review_status` or `status`)
- `config_version` (`str`)

---

## 9. Normalised Event Input Contract Consumed by T8

`normalize_event_for_reconstruction` accepts events containing:
- `event_id` (`str`, required)
- `case_id` (`str`, verified against active case)
- `evidence_id` (`str`)
- `event_type` (`str`, bridged with `action`)
- `event_time_utc` (`str | None`, ISO-8601 UTC timestamp, bridged with `timestamp`)
- `raw_timestamp` (`str | None`, original un-normalized timestamp from artifact)
- `source_locator` (`str | dict`, bridged with `artifact_ref`)
- `extraction_quality` (`str | dict`, preserved along with `extraction_quality_details`)

---

## 10. Hypothesis Output Contract Produced by T7

Each `RankedHypothesis.to_dict()` includes:
- `id`, `kind`, `name`, `description`
- `case_id`, `analysis_run_id`, `correlation_config_version`
- `status` (`LEADING`, `VIABLE`, `WEAKENED`, `REFUTED`, `UNDETERMINED`)
- `inconsistency_score`, `rank`
- `conclusion_type` (`"MACHINE_HYPOTHESIS"`), `investigator_confirmed` (`False`)
- `supporting_claim_ids`, `contradicting_claim_ids`
- `supporting_relationship_ids`, `contradicting_relationship_ids`
- `primary_relationship_ids`, `secondary_relationship_ids`
- `supporting_evidence_ids`, `contradicting_evidence_ids`, `evidence_ids`
- `supporting_event_ids`, `contradicting_event_ids`, `source_event_ids`
- `hard_violations_count`, `missing_expected_count`, `unobservable_count`
- `evaluations` (per-item evaluation breakdown with `matched_claim_ids`, `matched_relationship_ids`, `evidence_ids`, `event_ids`, `witness_family`, `state`, and `rationale`)

---

## 11. Reconstructed Timeline Output Contract Produced by T8

`NarrativeReconstruction.to_dict()` includes:
- `hypothesis_id`, `hypothesis_name`, `status`, `case_id`, `analysis_run_id`
- `stages` (chronological stage views with `stage_name`, `status`, `time_window`, `relationship_to_previous`, `claims`, `raw_events`, `relationship_ids`, `contradictions`, `chronology_uncertainty`)
- `timeline_events` / `events` (chronologically ordered reconstructed events with `event_id`, `case_id`, `evidence_id`, `event_type`, `event_time_utc`, `raw_timestamp`, `source_locator`, `source_locator_details`, `extraction_quality`, `relationship_ids`, `relationships`, `hypothesis_ids`, `claim_ids`, `chronology_uncertainty`, `contradictions`, `analysis_run_id`)
- `evidence_ids`, `relationship_ids`
- `contradictions`, `chronology_uncertainties`
- `missing_timestamp_event_ids`, `missing_timestamp_events`
- `conflicting_timestamp_events`, `duplicate_event_ids`
- `background_activity_count`, `background_activity_event_ids`
- `residual_h0_count`, `residual_h0_event_ids`
- `narrative_summary`

---

## 12. Primary vs Secondary Relationship Handling

| Aspect | `PRIMARY` Relationship | `SECONDARY` Relationship |
|---|---|---|
| **Forensic Meaning** | Direct validated identifier/cryptographic anchor (`P01`–`P18`) | Weighted contextual/probabilistic association (`P19`–`P44`) |
| **T7 Claim Derivation** | Can derive `SAME_OBJECT_FLOW` (Grade `A`/`B`) and `ACTOR_DEVICE_CONSISTENT` | **Never** derives `SAME_OBJECT_FLOW`; derives at most Grade `C` `ACTOR_DEVICE_CONSISTENT` when above threshold and uncontested |
| **Auto-Confirmation Guard** | Cannot bypass disconfirmation margin or hard `forbids` violations | High score (`0.99`) alone can never satisfy `SAME_OBJECT_FLOW` or auto-confirm exfiltration |
| **Hypothesis Tracking** | Listed in `primary_relationship_ids` | Listed in `secondary_relationship_ids` |
| **T8 Timeline Tracking** | Attached to endpoint events with `relationship_type: "PRIMARY"` | Attached to endpoint events with `relationship_type: "SECONDARY"` and `score` |

---

## 13. Contradiction, Uncertainty and Missing-Evidence Handling

1. **Missing vs Unobservable vs Contradictory Evidence:**
   - Unreferenced or absent evidence outside monitored source coverage is classified as `UNOBSERVABLE` (strictly neutral, `0.0` penalty, never treated as contradictory).
   - Missing expected evidence inside an actively monitored coverage interval is classified as `MISSING` (adds disconfirmation penalty, never fabricated).
   - Explicit counter-signals or conflicting evidence derive `VIOLATED` forbid items or `CONTESTED` claims.
2. **Chronology Uncertainty:**
   - Events with missing timestamps are placed in `missing_timestamp_events` with `chronology_uncertainty.status = "MISSING_TIMESTAMP"`.
   - Events whose `raw_timestamp` conflicts with `event_time_utc` are flagged in `conflicting_timestamp_events` with `discrepancy_seconds`.
   - Overlapping stage intervals are marked `CONCURRENT_OR_OVERLAPPING` rather than asserting false precedence; reversed stage intervals are flagged as `OUT_OF_ORDER`.

---

## 14. Integration Boundaries with Shambhavi, Anupriya and Saiesha

1. **Anupriya (Role 2 — Evidence Acquisition & Parsing) -> Niharika (Role 4):**
   - T7 and T8 ingest normalised events produced by `evidence-engine` parsers (`gmail`, `outlook`, `pst`, `pcap`, `zeek`, `log`, `browser`, `chat`, `image`) and preserve `evidence_id`, `sha256`, `parser_version`, and `source_locator`.
2. **Shambhavi (Role 1 — Correlation Engine) -> Niharika (Role 4):**
   - `execute_analysis_run`, `evaluate_hypotheses`, and `reconstruct_narrative` consume `CorrelationResult.relationships` from `correlate_case_events` (or caller-provided validated relationships) without duplicating correlation logic.
3. **Niharika (Role 4) -> Saiesha (Role 3 — Case Workflow & PDF Reporting):**
   - `execute_analysis_run` and `get_run_details` expose all immutable run metadata, T7 ranked hypotheses, and T8 reconstructions required by `load_report_inputs`, `build_report_content`, and `render_report_pdf` in `backend/app/reports/run_report.py`.

---

## 15. Sample JSON Payloads

### 15.1 Primary Relationship Input Consumed by T7
```json
{
  "relationship_id": "rel_1111111111111111111111111111111111111111111111111111111111111111",
  "case_id": "CASE-E2E-PIPELINE",
  "source_event_id": "CASE-E2E-PIPELINE:EV-02",
  "target_event_id": "CASE-E2E-PIPELINE:EV-03",
  "relationship_type": "PRIMARY",
  "score": null,
  "threshold_version": "1.0.0-provisional",
  "feature_contributions": [
    {
      "parameter_id": "P01_EXACT_MESSAGE_ID",
      "kind": "anchor",
      "value": 1.0,
      "weight": 1.0,
      "contribution": 1.0,
      "status": "ANCHORED"
    }
  ],
  "counter_signals": [],
  "explanation": "Validated direct PRIMARY relationship via exact RFC Message-ID <exfil-901@corp.example>.",
  "evidence_refs": [
    "CASE-E2E-PIPELINE-EV-GMAIL",
    "CASE-E2E-PIPELINE-EV-PST"
  ],
  "review_status": "VALIDATED_DIRECT",
  "config_version": "corr-config-v1"
}
```

### 15.2 Secondary Relationship Input Consumed by T7
```json
{
  "relationship_id": "rel_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "case_id": "CASE-E2E-PIPELINE",
  "source_event_id": "CASE-E2E-PIPELINE:EV-04",
  "target_event_id": "CASE-E2E-PIPELINE:EV-05",
  "relationship_type": "SECONDARY",
  "score": 0.84,
  "threshold_version": "1.0.0-provisional",
  "feature_contributions": [
    {
      "parameter_id": "P19_TEMPORAL_PROXIMITY",
      "kind": "feature",
      "value": 0.92,
      "weight": 0.12,
      "contribution": 0.1104
    }
  ],
  "counter_signals": [],
  "explanation": "Secondary network-to-browser temporal and endpoint correlation.",
  "evidence_refs": [
    "CASE-E2E-PIPELINE-EV-ZEEK",
    "CASE-E2E-PIPELINE-EV-WEB"
  ],
  "review_status": "HIGH_CONFIDENCE",
  "config_version": "corr-config-v1"
}
```

### 15.3 Evidence-Backed Hypothesis Output Produced by T7
```json
{
  "id": "H1",
  "kind": "insider_exfiltration",
  "name": "Insider Exfiltration",
  "description": "An account holder intentionally accesses, stages, archives and uploads sensitive information.",
  "case_id": "CASE-E2E-PIPELINE",
  "analysis_run_id": "RUN-8F4A2C19B001",
  "correlation_config_version": "corr-config-v1",
  "status": "VIABLE",
  "inconsistency_score": 0.8,
  "rank": 1,
  "conclusion_type": "MACHINE_HYPOTHESIS",
  "investigator_confirmed": false,
  "supporting_claim_ids": [
    "3c9b71e2d1a04f89a6e5c4b3a291807f6e5d4c3b2a1908f7e6d5c4b3a291807f"
  ],
  "contradicting_claim_ids": [],
  "supporting_relationship_ids": [
    "rel_1111111111111111111111111111111111111111111111111111111111111111",
    "rel_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  ],
  "contradicting_relationship_ids": [],
  "primary_relationship_ids": [
    "rel_1111111111111111111111111111111111111111111111111111111111111111"
  ],
  "secondary_relationship_ids": [
    "rel_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  ],
  "supporting_evidence_ids": [
    "CASE-E2E-PIPELINE-EV-GMAIL",
    "CASE-E2E-PIPELINE-EV-LOG",
    "CASE-E2E-PIPELINE-EV-PST",
    "CASE-E2E-PIPELINE-EV-WEB",
    "CASE-E2E-PIPELINE-EV-ZEEK"
  ],
  "contradicting_evidence_ids": [],
  "evidence_ids": [
    "CASE-E2E-PIPELINE-EV-GMAIL",
    "CASE-E2E-PIPELINE-EV-LOG",
    "CASE-E2E-PIPELINE-EV-PST",
    "CASE-E2E-PIPELINE-EV-WEB",
    "CASE-E2E-PIPELINE-EV-ZEEK"
  ],
  "supporting_event_ids": [
    "CASE-E2E-PIPELINE:EV-01",
    "CASE-E2E-PIPELINE:EV-02",
    "CASE-E2E-PIPELINE:EV-03",
    "CASE-E2E-PIPELINE:EV-04",
    "CASE-E2E-PIPELINE:EV-05"
  ],
  "contradicting_event_ids": [],
  "source_event_ids": [
    "CASE-E2E-PIPELINE:EV-01",
    "CASE-E2E-PIPELINE:EV-02",
    "CASE-E2E-PIPELINE:EV-03",
    "CASE-E2E-PIPELINE:EV-04",
    "CASE-E2E-PIPELINE:EV-05"
  ],
  "hard_violations_count": 0,
  "missing_expected_count": 1,
  "unobservable_count": 1
}
```

### 15.4 Reconstructed Timeline Event with Source Locator Produced by T8
```json
{
  "event_id": "CASE-E2E-PIPELINE:EV-03",
  "case_id": "CASE-E2E-PIPELINE",
  "evidence_id": "CASE-E2E-PIPELINE-EV-PST",
  "event_type": "email_sent",
  "action": "email_sent",
  "source": "pst",
  "family": "pst",
  "event_time_utc": "2026-10-18T02:02:05Z",
  "timestamp": "2026-10-18T02:02:05",
  "raw_timestamp": "2026-10-18T02:02:05Z",
  "source_locator": "pst:/Top of Personal Folders/Sent Items#item_id=2097188&message_id=<exfil-901@corp.example>",
  "artifact_ref": "pst:/Top of Personal Folders/Sent Items#item_id=2097188&message_id=<exfil-901@corp.example>",
  "source_locator_details": {
    "artifact_ref": "pst:/Top of Personal Folders/Sent Items#item_id=2097188&message_id=<exfil-901@corp.example>",
    "message_id": "<exfil-901@corp.example>",
    "pst_folder_path": "/Top of Personal Folders/Sent Items",
    "pst_item_id": "2097188"
  },
  "extraction_quality": {
    "tz_assumption": "explicit_offset",
    "timezone_certainty": "explicit",
    "timestamp_quality": "explicit_utc",
    "clock_offset_seconds": 0.0,
    "clock_uncertainty_seconds": 0.0,
    "parser_version": "pst_parser@1.1.0"
  },
  "chronology_uncertainty": {
    "status": "DEFINITE",
    "effective_interval": {
      "lo": "2026-10-18T02:02:05Z",
      "hi": "2026-10-18T02:02:05Z"
    },
    "clock_offset_seconds": 0.0,
    "clock_uncertainty_seconds": 0.0,
    "tz_assumption": "explicit_offset",
    "timezone_certainty": "explicit",
    "timestamp_quality": "explicit_utc",
    "has_uncertainty": false,
    "has_timestamp_conflict": false,
    "discrepancy_seconds": null,
    "ordering_certainty": "DEFINITE"
  },
  "relationship_ids": [
    "rel_1111111111111111111111111111111111111111111111111111111111111111"
  ],
  "hypothesis_ids": [
    "H1"
  ],
  "contradictions": [],
  "analysis_run_id": "RUN-8F4A2C19B001"
}
```

### 15.5 Immutable Analysis-Run Manifest
```json
{
  "run_id": "RUN-8F4A2C19B001",
  "case_id": "CASE-E2E-PIPELINE",
  "status": "COMPLETED",
  "started_at": "2026-11-24T11:50:12.104821+00:00",
  "completed_at": "2026-11-24T11:50:12.148902+00:00",
  "input_evidence_hashes": [
    {
      "evidence_id": "CASE-E2E-PIPELINE-EV-GMAIL",
      "sha256": "8c0e44291321c9f6211145a9e2b33f5a0c4e1b2d3f4a5b6c7d8e9f0a1b2c3d4e"
    },
    {
      "evidence_id": "CASE-E2E-PIPELINE-EV-LOG",
      "sha256": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
    },
    {
      "evidence_id": "CASE-E2E-PIPELINE-EV-PST",
      "sha256": "3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e"
    },
    {
      "evidence_id": "CASE-E2E-PIPELINE-EV-WEB",
      "sha256": "5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b"
    },
    {
      "evidence_id": "CASE-E2E-PIPELINE-EV-ZEEK",
      "sha256": "7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d"
    }
  ],
  "parser_versions": {
    "known": [
      "browser_csv@1.1.0",
      "gmail_json@1.1.0",
      "log_csv@1.1.0",
      "pst_parser@1.1.0",
      "zeek_conn@1.1.0"
    ],
    "unknown_evidence_ids": []
  },
  "correlation_config_version": "corr-config-v1",
  "correlation_registry_version": "1.0.0-provisional",
  "module_versions": {
    "engine": "pramana-engine@1.0.0",
    "t5_link_engine": "t5-link-engine@1.0.0",
    "correlation_engine": "correlation@1.0.0-provisional",
    "t6_claims_engine": "t6-claims-engine@1.0.0",
    "t7_hypothesis_engine": "t7-hyp-engine@1.1.0",
    "t8_reconstruction_engine": "t8-reconstruct@1.1.0",
    "t8_immutable_runs": "t8-runs@1.1.0"
  },
  "output_manifest_hash": "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b"
}
```

---

## 16. Test Coverage Added

1. **`intelligence/tests/test_t7_relationship_compatibility.py` (18 tests):**
   - `test_primary_relationship_consumed_by_t7`
   - `test_secondary_relationship_consumed_by_t7_preserves_primary_secondary_distinction`
   - `test_supporting_and_contradicting_evidence_and_relationship_references`
   - `test_multiple_relationships_contributing_to_one_hypothesis`
   - `test_missing_evidence_references_never_treated_as_contradictory`
   - `test_invalid_or_incomplete_relationship_payloads_rejected` (10 parametrized invalid payload cases)
   - `test_deterministic_hypothesis_generation_with_relationships`
   - `test_case_isolation_enforced_in_t7`
   - `test_analysis_run_and_shambhavi_correlation_engine_direct_integration`
2. **`intelligence/tests/test_t8_event_relationship_compatibility.py` (7 tests):**
   - `test_normalised_event_ingestion_and_evidence_traceability`
   - `test_source_locator_traceability_across_all_required_forensic_sources`
   - `test_relationship_linked_reconstruction_preserves_primary_and_secondary_links`
   - `test_missing_and_conflicting_timestamps_handled_explicitly`
   - `test_chronology_uncertainty_and_contradictory_events_preserved`
   - `test_duplicate_event_handling_and_deterministic_reconstruction`
   - `test_case_isolation_enforced_in_t8`
3. **`backend/tests/test_t7_t8_integration_continuity.py` (3 tests):**
   - `test_phase4_immutable_analysis_run_manifest_and_continuity`
   - `test_phase4_deterministic_reproducibility_with_relationships`
   - `test_phase5_and_phase6_focused_end_to_end_pipeline_and_reporting_boundary`

---

## 17. Final Test Execution Results

| Suite | Collected | Passed | Skipped | Failed |
|---|---:|---:|---:|---:|
| **New Role 4 Compatibility & Integration Tests** | `28` | `28` | `0` | `0` |
| **Existing T7 & T8 Unit + Backend Reproducibility Tests** | `92` | `92` | `0` | `0` |
| **Full Repository Test Suite (`python3 -m pytest -ra`)** | `1,055` | `1,046` | `9` | `0` |

*(The 9 skipped tests are PostgreSQL live-database migration tests in `backend/tests/test_postgres_migration.py` gated on `PRAMANA_TEST_PG_URL`.)*

---

## 18. Known Limitations and Future Work

1. **Provisional Correlation Thresholds:** Shambhavi's correlation registry (`1.0.0-provisional`) uses uncalibrated provisional thresholds for secondary scoring. T7 therefore treats `SECONDARY` relationships strictly as Grade `C` contextual signals and never promotes them to direct object-flow evidence.
2. **Report Section Rendering of Correlation Parameters:** Saiesha's immutable PDF report generator (`backend/app/reports/run_report.py`) currently renders static `"Unavailable"` placeholders for per-relationship scores in Section 4 (`UNAVAILABLE_FIELDS["relationship_score"]`), which is locked by `backend/tests/test_run_reports.py`. Now that `relationships` are persisted in `RunSnapshot.snapshot["relationships"]`, a future coordinated update with Role 3 can render those stored relationships directly in the PDF table.

---

## 19. Quick Verification Commands for Teammates and Mentors

```bash
# 1. Run all new Role 4 compatibility and end-to-end integration tests
python3 -m pytest \
  intelligence/tests/test_t7_relationship_compatibility.py \
  intelligence/tests/test_t8_event_relationship_compatibility.py \
  backend/tests/test_t7_t8_integration_continuity.py -v

# 2. Run all T7 and T8 unit and reproducibility suites
python3 -m pytest \
  intelligence/tests/test_t7_*.py \
  intelligence/tests/test_t8_*.py \
  backend/tests/test_t8_*.py -v

# 3. Run the complete repository regression suite
python3 -m pytest -ra
```
