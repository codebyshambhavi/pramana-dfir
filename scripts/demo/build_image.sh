#!/usr/bin/env bash
# Role 4 / T12: build the demo image if it is missing: python:3.12-slim with the backend, evidence-engine and
# intelligence requirements plus httpx (used by demo_run.py). Code is not baked in; the scripts mount the repo.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${DEMO_IMAGE:-pramana-t11-backend-deps:local}"
docker build -t "$IMAGE" -f - "$ROOT" <<'EOF'
FROM python:3.12-slim
COPY backend/requirements.txt backend/requirements.txt
COPY evidence-engine/requirements.txt evidence-engine/requirements.txt
COPY intelligence/requirements.txt intelligence/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt -r evidence-engine/requirements.txt -r intelligence/requirements.txt httpx
EOF
echo "Built $IMAGE"
