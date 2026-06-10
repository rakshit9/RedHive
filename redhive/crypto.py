"""Symmetric encryption for secrets at rest (e.g. integration tokens).

We never store a third-party access token in plaintext. Tokens are encrypted
with Fernet (AES-128-CBC + HMAC) using a key derived from ``settings.secret_key``
so rotating the app secret invalidates stored tokens (fail-safe). For a
hardened deployment, swap this for a KMS-backed key — the interface
(``encrypt``/``decrypt``) stays the same.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from redhive.config import settings


def _fernet() -> Fernet:
    # Derive a stable 32-byte key from the app secret, urlsafe-b64 for Fernet.
    digest = hashlib.sha256(settings.secret_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(ciphertext: str) -> str | None:
    """Return the plaintext, or None if the token can't be decrypted (e.g. the
    app secret changed). Callers treat None as 'integration needs reconnecting'."""
    try:
        return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return None
