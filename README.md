# Pramana (pramana-dfir)

Local-first digital forensics framework for SUTRAM 2026. Evidence is hash-verified once at intake, correlated across sources, and every AI finding links back to the original evidence.

> Every finding, proven to its source.

## Roles, branches and folders

| Role | Branch | Folders |
| --- | --- | --- |
| 1 Evidence engine | `role1/evidence-engine` | `evidence-engine/`, `datasets/`, `contracts/event.schema.json` |
| 2 Intelligence | `role2/intelligence` | `intelligence/`, `contracts/finding.schema.json` |
| 3 Backend and graph | `role3/backend-graph` | `backend/`, `docker-compose.yml`, `.github/`, `contracts/openapi.yaml` |
| 4 Frontend and docs | `role4/frontend-docs` | `frontend/`, `docs/`, `README.md` |

Rules: work only on your branch and in your folders; merge to `main` by pull request; prefix commits with your role (`[R1] add pcap parser`); never commit real evidence or secrets; contracts change only by an issue all four approve.

## Data flow

```
files -> [R1] parse_evidence() -> Event JSON -> [R3] store + graph -> [R2] analyze() -> Finding JSON -> [R3] lineage + report -> [R4] console
```

Python hand-offs (called by the backend):

- `parsers.parse_evidence(path, case_id) -> list[dict]`  (Role 1, in `evidence-engine/`)
- `intelligence.analyze(events) -> list[dict]`  (Role 2, in `intelligence/`)

The folder `evidence-engine/` has a hyphen, so it is put on `PYTHONPATH` rather than imported by name. From the repo root:

```bash
export PYTHONPATH=evidence-engine:.
```

## First-time setup (repo owner, Role 3)

```bash
git init -b main
git add . && git commit -m "[R3] Initial repo skeleton"
git remote add origin https://github.com/<you>/pramana-dfir.git
git push -u origin main

for b in role1/evidence-engine role2/intelligence role3/backend-graph role4/frontend-docs; do
  git branch $b && git push origin $b
done
```

Then edit `.github/CODEOWNERS` with the four GitHub usernames and add the others as collaborators.

## Run

```bash
cp .env.example .env
docker compose up --build      # postgres + backend on http://localhost:8000/docs
cd frontend && npm install && npm run dev
```

Evidence in `datasets/` is synthetic only.
