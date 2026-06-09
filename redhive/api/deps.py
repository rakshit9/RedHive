"""FastAPI dependencies — auth, tenancy, and DB sessions.

Every protected endpoint depends on ``require_auth`` which resolves an
``AuthContext`` (the org the caller acts as) from either:

- an **API key**: ``Authorization: Bearer rh_<prefix>_<secret>`` — for the
  public/programmatic API and CI integrations, or
- a **session token**: ``Authorization: Bearer <signed-token>`` — issued by the
  dashboard login flow.

Resolution is constant-time on the hashed key and never leaks which arm failed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, status

from redhive import repository as repo
from redhive.database import session_scope
from redhive.security import hash_api_key, parse_api_key_prefix, verify_session_token


@dataclass
class AuthContext:
    """Who is making the request, and which tenant they act as."""

    org_id: uuid.UUID
    user_id: uuid.UUID | None = None
    api_key_id: uuid.UUID | None = None
    via: str = "api_key"  # "api_key" | "session"


_UNAUTH = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Missing or invalid credentials.",
    headers={"WWW-Authenticate": "Bearer"},
)


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()


def _resolve_api_key(token: str) -> AuthContext | None:
    """An API key looks like ``rh_<prefix>_<secret>``; verify by hash."""
    if parse_api_key_prefix(token) is None:
        return None
    with session_scope() as db:
        key = repo.get_api_key_by_hash(db, hash_api_key(token))
        if key is None:
            return None
        repo.touch_api_key(db, key)
        return AuthContext(org_id=key.org_id, api_key_id=key.id, via="api_key")


def _resolve_session(token: str) -> AuthContext | None:
    payload = verify_session_token(token)
    if payload is None:
        return None
    try:
        return AuthContext(
            org_id=uuid.UUID(payload["org"]),
            user_id=uuid.UUID(payload["uid"]),
            via="session",
        )
    except (KeyError, ValueError):
        return None


def require_auth(authorization: str | None = Header(default=None)) -> AuthContext:
    """Resolve the caller's org from an API key or session token, or 401."""
    token = _bearer(authorization)
    if token is None:
        raise _UNAUTH
    ctx = _resolve_api_key(token) or _resolve_session(token)
    if ctx is None:
        raise _UNAUTH
    return ctx


def require_session(ctx: AuthContext = Depends(require_auth)) -> AuthContext:
    """For dashboard-only endpoints (e.g. key management) that must not be
    callable with an API key — prevents a leaked key from minting more keys."""
    if ctx.via != "session":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint requires a logged-in dashboard session.",
        )
    return ctx
