"""Unit tests for security primitives."""

from __future__ import annotations

import time

from redhive import security


def test_password_hash_roundtrip():
    h = security.hash_password("s3cret-password")
    assert h != "s3cret-password"
    assert security.verify_password("s3cret-password", h)
    assert not security.verify_password("wrong", h)


def test_verify_password_handles_garbage():
    assert not security.verify_password("x", "not-a-bcrypt-hash")


def test_api_key_generation_and_hash():
    full, prefix, key_hash = security.generate_api_key()
    assert full.startswith("rh_")
    assert security.parse_api_key_prefix(full) == prefix
    assert security.hash_api_key(full) == key_hash
    # Different keys -> different hashes.
    full2, _, key_hash2 = security.generate_api_key()
    assert key_hash != key_hash2


def test_parse_api_key_prefix_rejects_malformed():
    assert security.parse_api_key_prefix("bogus") is None
    assert security.parse_api_key_prefix("xx_abc_def") is None


def test_session_token_roundtrip():
    token = security.issue_session_token("user-1", "org-1")
    payload = security.verify_session_token(token)
    assert payload is not None
    assert payload["uid"] == "user-1"
    assert payload["org"] == "org-1"


def test_session_token_tamper_rejected():
    token = security.issue_session_token("user-1", "org-1")
    payload_b64, sig = token.split(".", 1)
    tampered = payload_b64 + "x." + sig
    assert security.verify_session_token(tampered) is None


def test_session_token_expiry(monkeypatch):
    token = security.issue_session_token("u", "o")
    # Advance the clock past the TTL by patching the module's time source.
    real = time.time()
    monkeypatch.setattr(security.time, "time", lambda: real + 10**9)
    assert security.verify_session_token(token) is None
