"""Security primitives — password hashing, API keys, session tokens.

Kept dependency-light and self-contained so auth logic has one obvious home.

- Passwords: bcrypt (per-password salt, slow by design).
- API keys: a random secret shown once as ``rh_<prefix>_<secret>``; only a
  SHA-256 hash of the full key is stored. Lookups hash the presented key and
  compare in constant time.
- Sessions: compact signed tokens (HMAC-SHA256 over a JSON payload) for the
  dashboard — no extra JWT dependency, same security properties for our use.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any

import bcrypt

from redhive.config import settings

# --------------------------------------------------------------------------- #
# Passwords                                                                   #
# --------------------------------------------------------------------------- #


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
# API keys                                                                    #
# --------------------------------------------------------------------------- #

_KEY_PREFIX = "rh"


def generate_api_key() -> tuple[str, str, str]:
    """Mint a new API key.

    Returns ``(full_key, prefix, key_hash)``. ``full_key`` is shown to the user
    exactly once; only ``prefix`` (for display) and ``key_hash`` are persisted.
    """
    prefix = secrets.token_hex(4)  # 8 hex chars, shown in the UI to identify keys
    secret = secrets.token_urlsafe(32)
    full_key = f"{_KEY_PREFIX}_{prefix}_{secret}"
    return full_key, prefix, hash_api_key(full_key)


def hash_api_key(full_key: str) -> str:
    """One-way hash of a full API key, used for storage and lookup."""
    return hashlib.sha256(full_key.encode("utf-8")).hexdigest()


def parse_api_key_prefix(full_key: str) -> str | None:
    """Extract the visible prefix from a presented key, or None if malformed."""
    parts = full_key.split("_", 2)
    if len(parts) == 3 and parts[0] == _KEY_PREFIX:
        return parts[1]
    return None


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


# --------------------------------------------------------------------------- #
# Session tokens (signed, stateless)                                          #
# --------------------------------------------------------------------------- #


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _sign(payload_b64: str) -> str:
    sig = hmac.new(settings.secret_key.encode("utf-8"), payload_b64.encode("ascii"), hashlib.sha256).digest()
    return _b64e(sig)


def issue_session_token(user_id: str, org_id: str) -> str:
    """Sign a session token for a dashboard user."""
    payload = {
        "uid": user_id,
        "org": org_id,
        "exp": int(time.time()) + settings.session_ttl_minutes * 60,
    }
    payload_b64 = _b64e(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    return f"{payload_b64}.{_sign(payload_b64)}"


def verify_session_token(token: str) -> dict[str, Any] | None:
    """Return the payload if the token is valid and unexpired, else None."""
    try:
        payload_b64, sig = token.split(".", 1)
    except ValueError:
        return None
    if not constant_time_equals(sig, _sign(payload_b64)):
        return None
    try:
        payload = json.loads(_b64d(payload_b64))
    except (ValueError, json.JSONDecodeError):
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload
