"""Scope guard -- the safety brake of RedHive.

This is the single chokepoint that prevents the platform from ever scanning a
target it is not authorized to touch. Every agent/tool MUST call
`assert_allowed(target)` before sending a single packet at a host.

A target is permitted only if its host matches an entry in
`settings.allowlist` (case-insensitive). Both bare hosts ("localhost",
"juiceshop:3000") and full URLs ("http://localhost:3000/login") are accepted.
"""

from __future__ import annotations

from urllib.parse import urlparse

from redhive.config import settings


class ScopeError(Exception):
    """Raised when a target is outside the authorized scan allowlist."""


def _extract_host(target: str) -> str:
    """Pull the bare hostname (no scheme, port, or path) out of a target.

    Accepts full URLs ("https://host:443/path") and bare hosts
    ("host", "host:3000"). Returns "" if nothing usable is found.
    """
    raw = (target or "").strip()
    if not raw:
        return ""

    # urlparse only finds a netloc when a scheme is present, so prepend one
    # for bare hosts like "localhost:3000" or "example.com/path".
    if "://" not in raw:
        raw = "//" + raw

    parsed = urlparse(raw, scheme="http")
    # .hostname strips any user:pass@ and :port, and lowercases the result.
    return (parsed.hostname or "").lower()


def is_allowed(target: str) -> bool:
    """Return True if `target`'s host is in the configured allowlist."""
    host = _extract_host(target)
    if not host:
        return False
    return host in settings.allowlist


def assert_allowed(target: str) -> None:
    """Raise ScopeError unless `target` is in scope. No-op when allowed."""
    if not is_allowed(target):
        host = _extract_host(target) or "<unparseable>"
        raise ScopeError(
            f"Target {target!r} (host {host!r}) is not in the scan allowlist "
            f"{settings.allowlist}. Refusing to scan unauthorized targets."
        )
