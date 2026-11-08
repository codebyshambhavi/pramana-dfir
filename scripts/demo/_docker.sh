# Role 4 / T12: shared settings for the demo scripts. Sourced, not run.
DEMO_IMAGE="${DEMO_IMAGE:-pramana-t11-backend-deps:local}"
DEMO_ENV=(
  -e PYTHONUNBUFFERED=1
  -e PYTHONDONTWRITEBYTECODE=1
  -e DATABASE_URL=sqlite:////tmp/pramana.db
  -e UPLOAD_DIR=/tmp/uploads
  -e DEMO_MODE=1
  -e PYTHONPATH=/w/backend:/w/evidence-engine:/w/intelligence:/w
)

# Docker on Windows (Git Bash) needs C:/... paths and no MSYS path rewriting.
host_path() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}
demo_docker() { MSYS_NO_PATHCONV=1 docker "$@"; }

if ! demo_docker image inspect "$DEMO_IMAGE" >/dev/null 2>&1; then
  echo "Image $DEMO_IMAGE not found. Build it with scripts/demo/build_image.sh, or set DEMO_IMAGE." >&2
  exit 1
fi
