"""API key authentication for the central enrichment server."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CLIENT_API_KEYS_PATH = PROJECT_ROOT / "config" / "clients" / "api_keys.json"

bearer_scheme = HTTPBearer(auto_error=False)


def _load_client_api_keys() -> dict[str, str]:
    keys: dict[str, str] = {}

    if CLIENT_API_KEYS_PATH.exists():
        payload = json.loads(CLIENT_API_KEYS_PATH.read_text(encoding="utf-8"))
        keys.update(payload.get("clients", {}))

    env_keys = os.getenv("CENTRAL_CLIENT_API_KEYS")
    if env_keys:
        keys.update(json.loads(env_keys))

    return keys


def get_master_api_key() -> Optional[str]:
    return os.getenv("CENTRAL_API_KEY")


def verify_client_api_key(client_id: str, provided_key: str) -> bool:
    client_keys = _load_client_api_keys()
    expected = client_keys.get(client_id)
    if not expected:
        return False
    return provided_key == expected


def verify_request_api_key(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    client_id: Optional[str] = None,
) -> str:
    """
    Validate Bearer token against master key or per-client key.

    If CENTRAL_API_KEY is unset and no client keys are configured, auth is disabled
    for local development.
    """
    master_key = get_master_api_key()
    client_keys = _load_client_api_keys()

    if not master_key and not client_keys:
        return "auth_disabled"

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header. Use: Bearer <api_key>",
        )

    provided_key = credentials.credentials

    if master_key and provided_key == master_key:
        return "master"

    if client_id and verify_client_api_key(client_id, provided_key):
        return f"client:{client_id}"

    if client_id is None:
        for configured_client_id, expected_key in client_keys.items():
            if provided_key == expected_key:
                return f"client:{configured_client_id}"

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid API key.",
    )


def require_api_key(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> str:
    return verify_request_api_key(credentials=credentials)


def require_client_api_key(client_id: str):
    def _dependency(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    ) -> str:
        return verify_request_api_key(credentials=credentials, client_id=client_id)

    return _dependency
