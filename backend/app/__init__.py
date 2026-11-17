"""PRAMANA backend package.

The routers import the sibling packages (`intelligence`, the evidence-engine parsers) at module load.
docker-compose puts them on PYTHONPATH, but hosts that run backend/Dockerfile directly (Render) do not,
and the app then fails to start. Add the same entries here so startup does not depend on the environment.
"""

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
for _entry in (_REPO_ROOT / "intelligence", _REPO_ROOT / "evidence-engine", _REPO_ROOT):
    if _entry.is_dir() and str(_entry) not in sys.path:
        sys.path.append(str(_entry))
