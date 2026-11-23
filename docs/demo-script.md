# Demo script (T12): CASE-DEMO-IST in 100 seconds

Every step runs against the real backend. Nothing on screen is mocked: the vault, runs, tamper, quarantine and diff
are live API responses. The backup recording is the same sequence captured from a clean database
(`frontend/src/api/recorded/case-demo-ist/`), and `scripts/demo/check.sh` proves a fresh run still matches it.

## Before the demo (once, about 1 minute)

Needs Docker and Node. Uses the cached image `pramana-t11-backend-deps:local`; build it with
`scripts/demo/build_image.sh` if it is missing.

```bash
bash scripts/demo/serve.sh
```

This deletes any previous demo container, so the database and uploaded files start empty. It then starts the backend on
http://localhost:8000 with `DEMO_MODE=1` and seeds the starting state: case CASE-DEMO-IST, its five evidence files and
analysis run A.

```bash
cd frontend && VITE_API_URL=http://localhost:8000 VITE_CASE_ID=CASE-DEMO-IST npm run dev
```

Open http://localhost:5173/app/evidence and set the header switch to **UTC**. To run the demo again, rerun
`serve.sh` first.

## The 100 seconds

| Time | Screen | Do | Say |
|---|---|---|---|
| 0–15 s | Evidence Vault | Point at the five files. Open `browser_history.csv` (EVID-002). | "Five sources for one laptop. Each file's SHA-256 is taken at intake and every action is hash-chained in custody." |
| 15–25 s | Drawer, Details | Show status ACTIVE and the SHA-256. | "Integrity status comes from the backend, not the browser." |
| 25–40 s | Investigation › Hypotheses | Show run A ranking: H2 Sanctioned Backup leading, H1 and H3 weakened. Open one matrix row. | "Each hypothesis is checked item by item against the evidence. Nothing is a confidence score." |
| 40–50 s | Claims tab | Open a claim and follow its lineage to an event and its SHA-256. | "Every claim traces to stored events and the file hash." |
| 50–65 s | Vault › EVID-002 drawer | Click **Simulate tamper & verify**. | "Someone edits the stored file. Re-hashing gives MISMATCH, so the file is QUARANTINED and run A is invalidated." |
| 65–80 s | Investigation › Run diff | Click **New run from current evidence**. | "A new run uses only ACTIVE evidence. Run A is kept, write-once." |
| 80–95 s | Run diff | Show EVID-002 removed, the three claims that depended on it removed, H2 LEADING → WEAKENED (rank 1 → 3), outcome LEADING → UNDETERMINED. | "The diff shows exactly what the tampered file was holding up." |
| 95–100 s | Header switch | Switch **UTC → IST**. | "Display only: 10:41 UTC reads 16:11 IST. Stored timestamps never change." |

Expected result: the engine ranks **H2 Sanctioned Backup** first, while the scenario's ground truth is H1. This is the
engine's real output (also in `bench/results/results.json`). Do not edit data to change it.

## If the live demo fails

1. Play the backup screen recording of this script.
2. Or open the recorded run with no backend: http://localhost:5173/app/investigation?tab=hypotheses&source=demo
   (Hypotheses, Claims, Reconstruction and Run diff tabs show the recorded CASE-DEMO-IST responses).

## Acceptance check

```bash
bash scripts/demo/check.sh 3
```

Runs the whole sequence over HTTP three times in a row. Each run starts a new container with an empty database and
upload folder. Per run it checks:

- the full API sequence finishes within the 100 s budget,
- the 31 recording checks pass (`validate_recording.py`),
- the result matches the committed recording on every compared field (`compare.py`).

Run IDs and custody times differ per run, so they are not compared. Output goes to `.demo-runs/`, which is git-ignored.
