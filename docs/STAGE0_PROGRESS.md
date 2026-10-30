# Stage 0 progress (T0 + T1 + T2)

Stage 0 is being delivered in two halves. This file records exactly where it stands.

## Half 1 — DONE: T0 + T1

### T0 — hygiene and deterministic execution
- Removed from the tree: `.env`, `backend/pramana.db`, `backend/data/uploads/` test files, `frontend/dist/`, caches. (The committed `.env` was identical to `.env.example`: placeholder values only.)
- `.gitignore` rewritten; `/evidence/` is now anchored so `datasets/sample_case_001/evidence/` is no longer ignored.
- `.env.example` completed; root `requirements.txt` installs all three Python packages.
- `backend/app/services/pipeline.py`: `_parse_evidence_adapter` and `_analyze_adapter` deleted, inline schema fallbacks deleted, `except ... pass` deleted. Failures raise (`PipelineError`, `ValueError`, schema errors).
- Event schema is mandatory in the dispatcher (was silently skipped when missing).
- Image parser no longer substitutes the file modification time when EXIF has no timestamp; it raises.
- Upload router: no silent intake-time timestamp substitute; unsupported/malformed evidence returns HTTP 422, rolls back the database and removes the stored file.
- Backend tests run on a temporary DB/upload dir (they used to create `backend/pramana.db` and `backend/data/uploads/`).

### T1 — parser correctness, Event v1.1
- Chat `device_gps` → `Event.location` (malformed GPS raises). `ip_location` stays in `raw` only.
- Canonical action vocabulary (`parsers/vocabulary.py`): `archive_created → archive_create`, `upload → file_upload`; original kept in `raw`.
- Event schema v1.1 (additive): optional `parser_version`, `tz_assumption`, `family`. Mirrored in `contracts/openapi.yaml` and `frontend/src/api/types.ts`.
- `correlate` matches a `file_upload` URL to an archive event by the uploaded file name.
- `GROUND_TRUTH.md` had a stale chat event ID; fixed and now guarded by a test.
- sample_case_001: all 3 planted items are detected (parser+intelligence and through the API).

## Half 2 — DONE: T2 time foundations
- `intelligence/timeline.py` (new): `SourceClock` (offset + uncertainty), `TimeInterval[lo, hi]` with `definitely_before` (A.hi < B.lo) / `possibly_before` (A.lo < B.hi) / `overlaps`, `effective_interval`, `sort_by_interval` (deterministic: lo, hi, event_id), `to_case_time`, and loading of `PRAMANA_SOURCE_CLOCKS`.
- `intelligence/config.py`: `SOURCE_CLOCKS_ENV_VAR`, `ODD_HOUR_ACTIONS`. The existing `PRAMANA_INTEL_TIMEZONE` mechanism is the case timezone (no second config system).
- `intelligence/anomalies.py`: odd-hour rule now (a) only for login/session actions (`login`, `auth`, `authenticate`, `session_start`), (b) in the configured case timezone, (c) on the offset-corrected time; clock uncertainty that straddles the window boundary yields a lower-confidence finding that says so.
- `intelligence/requirements.txt`: `tzdata`.
- Raw timestamps are never rewritten; naive timestamps still mean UTC.

### Decision: Event v1.1 fields stay non-persistent
`parser_version`, `tz_assumption` and `family` are present on every parsed Event and validated by the schema, but the backend database does not store them. T2 does not need them: the case timezone comes from configuration and source clocks are keyed by `Event.source`, which is stored. Persisting them would need new columns on a table that `create_all` cannot alter, i.e. a migration on the deployed Postgres, which is out of scope. Revisit when a feature genuinely needs `family` (source-independence accounting).

## Known open items
- `contradictions.py` (travel speed) and `correlate.py` (time windows) still use raw instants; they do not yet use intervals / source clocks.
- `sample_case_001` is a UTC case. Under `Asia/Kolkata` its login is 07:47 local and correctly not an odd-hour anomaly.
- PCAP packets with no timestamp or that fail to parse are skipped with a logged warning (evidence dropped, not silent).
- Unsupported evidence types (e.g. disk images) are rejected at upload (HTTP 422) instead of being vaulted with a placeholder event.
- README says Ollama is used by the intelligence layer; the code does not use it.
