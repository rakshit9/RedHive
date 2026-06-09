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
    """Return True if `target`'s host is scannable: either a built-in practice
    host (static config allowlist) or a customer host the API has authorized for
    this process after ownership verification."""
    host = _extract_host(target)
    if not host:
        return False
    return host in settings.allowlist or host in _authorized_hosts


def assert_allowed(target: str) -> None:
    """Raise ScopeError unless `target` is in the global practice allowlist.

    This is the tool-level chokepoint (defense in depth): every scan tool calls
    it before sending a packet, so even a logic bug upstream cannot make the
    agent touch an unlisted host. Customer hosts pass this only after the API
    has confirmed org ownership and added them to the runtime allowlist for the
    duration of the scan (see ``authorize_host``).
    """
    if not is_allowed(target):
        host = _extract_host(target) or "<unparseable>"
        raise ScopeError(
            f"Target {target!r} (host {host!r}) is not in the scan allowlist "
            f"{settings.allowlist}. Refusing to scan unauthorized targets."
        )


# Hosts a customer org has proven they own. The API adds verified targets here
# at scan-enqueue time so the tool-level ``assert_allowed`` accepts them without
# baking customer hosts into the static config allowlist.
_authorized_hosts: set[str] = set()


def authorize_host(target_or_host: str) -> None:
    """Mark a verified host as scannable for the running process."""
    host = _extract_host(target_or_host)
    if host:
        _authorized_hosts.add(host)


def host_for(target: str) -> str:
    """Public helper: the bare host of a target (lowercased)."""
    return _extract_host(target)
