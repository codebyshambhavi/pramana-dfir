# Recorded run: CASE-DEMO-IST

Real backend responses, saved verbatim. Nothing in this folder was written or edited by hand.

## Provenance

- **Code:** `43ba364` (`origin/main`, after T3/T4 #9, T5/T6 #10, T7/T8 #11, T9/T10 #12, T11 #13, T12 #14 and the
  evidence-engine/T7 coverage change #15). Re-recorded because #15 changed the hypothesis ranking; the first recording
  (`a6e9ffd`) is in git history.
- **Input:** the five T9 evidence files in `bench/scenarios/CASE-DEMO-IST/evidence/`, uploaded through `POST /cases/{id}/evidence`.
- **Backend:** uvicorn, Python 3.12, fresh SQLite database, Docker with networking switched off, `PYTHONPATH` as in `docker-compose.yml`.
- **Assumptions:** `{"case_timezone": "Asia/Kolkata"}`.
- **DEMO_MODE=1:** only enables `POST /evidence/{id}/simulate-tamper` (`backend/app/routers/integrity.py`). No analysis code reads it.
- **Recorded:** 2026-11-09 with `scripts/demo/demo_run.py full` on a new empty database. Every call and its status code
  is in `requests.json`. All returned 2xx.

## Sequence

| Step | Request | File |
|---|---|---|
| 1 | `POST /cases`, then `POST /cases/CASE-DEMO-IST/evidence` × 5 | `uploads.json` |
| 2 | `GET /cases/CASE-DEMO-IST/evidence`, `/events`, `/integrity` | `evidence_before.json`, `events.json`, `integrity_before.json` |
| 3 | `POST /cases/CASE-DEMO-IST/runs` → run A `RUN-869D4041830D` | `run_a_created.json` |
| 4 | `GET /runs/{A}`, `POST /runs/{A}/verify`, lineage of each claim | `run_a.json`, `run_a_verify.json`, `run_a_lineage.json` |
| 5 | `POST /evidence/EVID-002/simulate-tamper` (browser_history.csv) | `tamper.json` |
| 6 | `POST /evidence/EVID-002/verify` → MISMATCH, QUARANTINED | `verify_after_tamper.json` |
| 7 | `GET /cases/CASE-DEMO-IST/integrity`, `/evidence`, `GET /runs/{A}` | `integrity_after.json`, `evidence_after.json`, `run_a_after_quarantine.json` |
| 8 | `POST /cases/CASE-DEMO-IST/runs` with `parent_run_id` A → run B `RUN-509B67516AF2` | `run_b_created.json` |
| 9 | `GET /runs/{B}`, lineage of each claim, `GET /cases/CASE-DEMO-IST/runs` | `run_b.json`, `run_b_lineage.json`, `runs.json` |
| 10 | `GET /runs/{A}/diff/{B}` | `diff_a_b.json` |

`*_lineage.json` maps each claim ID to its `GET /runs/{run}/claims/{claim}/lineage` response.

## Reproducing (T12)

The recorder and checks are in `scripts/demo/`: `demo_run.py` (makes the calls in the order below), `validate_recording.py`
(the 31 checks) and `compare.py` (fresh run vs this folder). `bash scripts/demo/check.sh 3` runs all three, three times,
each on a new empty database. Run IDs and custody times change every run, so `compare.py` leaves them out and compares
everything else that is shown in the demo. To re-record, run `demo_run.py full` against a clean backend and copy its
output here, except `_timings.json`.

## Validation

`validation.txt` has 31 checks, all passing:
- API events match a direct run of the parsers (120 events).
- Every claim edge and lineage step resolves to a stored event and an intake SHA-256.
- Run A reproduces its ranking hash.
- Tamper, then verify, quarantines the file and invalidates run A.
- The diff removes exactly the claims that depended on the quarantined file.

Run A's `ranking_hash` is `b07937c1…e3598`, and `POST /runs/{id}/verify` reproduces it. The PRAMANA entry for this case in
`bench/results/results.json` still shows `aa71551d`, the hash from before #15; that file is owned by Role 1 and was not
re-run here.

## Known result: H2 leads, ground truth is H1

Run A ranks **H2 Sanctioned Backup** LEADING, H1 Insider Exfiltration WEAKENED and H3 Session Misuse WEAKENED (H3 was
REFUTED before #15). `bench/scenarios/CASE-DEMO-IST.yaml` gives `correct_hypothesis: H1` and expects `H2-EXP-2` to be
MISSING, but the engine reports UNOBSERVABLE. The top hypothesis is the same as in the committed benchmark (H2, so
`top_hypothesis_accuracy` 0.0 for this case).

After EVID-002 is quarantined, run B is UNDETERMINED with all three WEAKENED, ranked H1, H3, H2. The diff removes the
three claims that rested on EVID-002 and shows no reconstruction stage change.

This is the engine's real output, kept as recorded. Do not edit these files to show a different result. If T7 or the scenario changes, re-record.

## Contract status

The T4 responses follow `contracts/openapi.yaml`. The run, claim, lineage and diff responses have no OpenAPI response schema yet; their types are in `../../pending/runs.ts`. `index.ts` makes `tsc` check every file here against those types.
