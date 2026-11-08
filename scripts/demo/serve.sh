#!/usr/bin/env bash
# Role 4 / T12: reset and start the backend for the live demo.
#
# Removes any previous demo container (and with it the database and uploaded files), starts a new one on
# http://localhost:8000 with DEMO_MODE=1, then seeds the starting state: CASE-DEMO-IST, its five evidence files and
# analysis run A. The tamper, quarantine, run B and diff are then done live in the UI (see docs/demo-script.md).
#
# The repo is mounted read-only; the database and uploads live only inside the container. Stop with:
#   docker rm -f pramana-demo
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/demo/_docker.sh"
NAME="${DEMO_CONTAINER:-pramana-demo}"
PORT="${DEMO_PORT:-8000}"

demo_docker rm -f "$NAME" >/dev/null 2>&1 || true
demo_docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8000" \
  -v "$(host_path "$ROOT"):/w:ro" "${DEMO_ENV[@]}" "$DEMO_IMAGE" \
  sh -c 'cd /w/backend && exec uvicorn app.main:app --host 0.0.0.0 --port 8000' >/dev/null
echo "Backend container $NAME started on http://localhost:$PORT (clean database)."

demo_docker exec "$NAME" python /w/scripts/demo/demo_run.py seed /w/bench/scenarios/CASE-DEMO-IST/evidence /tmp/seed
echo "Seeded CASE-DEMO-IST with run A. Start the UI with:"
echo "  cd frontend && VITE_API_URL=http://localhost:$PORT VITE_CASE_ID=CASE-DEMO-IST npm run dev"
