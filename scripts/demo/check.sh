#!/usr/bin/env bash
# Role 4 / T12 acceptance: run the whole CASE-DEMO-IST demo N times (default 3) in a row, each on a clean database.
#
# Each run is a new throwaway container (--rm, no network) with an empty SQLite database and upload folder in its own
# /tmp, so nothing carries over between runs. The repo is mounted read-only. Per run it:
#   1. starts the backend (DEMO_MODE=1),
#   2. runs the demo over HTTP (demo_run.py full) within the 100 s budget,
#   3. runs the 31 recording checks (validate_recording.py),
#   4. compares the result with the committed recording (compare.py).
# Any failure stops the loop with a non-zero exit. Output goes to $DEMO_OUT (default .demo-runs/, git-ignored).
#
# Image: $DEMO_IMAGE (default pramana-t11-backend-deps:local, python:3.12-slim with the backend requirements and httpx
# installed). Build one with scripts/demo/build_image.sh if it is missing.
set -euo pipefail

RUNS="${1:-3}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$ROOT/scripts/demo/_docker.sh"
OUT="${DEMO_OUT:-$ROOT/.demo-runs}"
mkdir -p "$OUT"

for i in $(seq 1 "$RUNS"); do
  dir="$OUT/run-$i"
  rm -rf "$dir"
  mkdir -p "$dir"
  echo "== run $i/$RUNS (clean database) =="
  demo_docker run --rm --network none \
    -v "$(host_path "$ROOT"):/w:ro" -v "$(host_path "$dir"):/out" \
    "${DEMO_ENV[@]}" "$DEMO_IMAGE" sh -c '
      set -e
      cd /w/backend
      uvicorn app.main:app --host 127.0.0.1 --port 8000 > /out/_uvicorn.log 2>&1 &
      python /w/scripts/demo/demo_run.py full /w/bench/scenarios/CASE-DEMO-IST/evidence /out
      python /w/scripts/demo/validate_recording.py /out /w > /out/validation.txt || { cat /out/validation.txt; exit 1; }
      tail -1 /out/validation.txt
      python /w/scripts/demo/compare.py /w/frontend/src/api/recorded/case-demo-ist /out > /out/compare.txt || { cat /out/compare.txt; exit 1; }
      tail -1 /out/compare.txt
    '
done
echo "== $RUNS/$RUNS consecutive clean runs passed =="
