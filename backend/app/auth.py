"""Connector access boundary.

The repository has no existing user/authentication implementation.  Connector
routes therefore fail closed unless an external trusted bearer token is
configured.  This module intentionally does not accept or persist passwords,
OAuth secrets, or tokens.
"""
from __future__ import annotations

import hmac
import json
import os
from typing import Any

from fastapi import Header, HTTPException


def require_authenticated_case_access(
    case_id: str,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    token = os.getenv("PRAMANA_API_BEARER_TOKEN")
    if not token:
        raise HTTPException(status_code=503, detail="Connector authentication is not configured")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    supplied = authorization[7:].strip()
    if not hmac.compare_digest(supplied, token):
        raise HTTPException(status_code=401, detail="Invalid authentication token")

    raw_cases = os.getenv("PRAMANA_AUTHORIZED_CASE_IDS")
    if raw_cases:
        try:
            case_ids = set(json.loads(raw_cases))
        except (json.JSONDecodeError, TypeError):
            raise HTTPException(status_code=503, detail="Case authorization configuration is invalid")
        if case_id not in case_ids:
            raise HTTPException(status_code=403, detail="Forbidden for this case")
    return {"actor": "authenticated-api-user", "case_id": case_id}
