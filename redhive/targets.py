"""Target ownership verification.

Before RedHive will scan a customer host, the customer must prove they control
it — the same trust model as Google Search Console or a TLS CA. Two methods:

- **DNS TXT**: add a ``TXT`` record at ``_redhive-verify.<host>`` whose value is
  the org's verification token.
- **HTTP file**: serve the token at ``http(s)://<host>/.well-known/redhive-verify.txt``.

This module owns token generation and the two probes. The scope guard
(``redhive.scope``) consults verified ``Target`` rows so an unverified or
unknown host is refused before any scan packet is sent. Built-in practice
targets (Juice Shop / localhost) bypass verification.
"""

from __future__ import annotations

import secrets

import httpx

from redhive.config import settings


def new_verification_token() -> str:
    """A high-entropy token the customer publishes to prove ownership."""
    return "redhive-verify=" + secrets.token_urlsafe(24)


def dns_record_name(host: str) -> str:
    return f"{settings.ownership_dns_prefix}.{host}"


def well_known_url(host: str, *, scheme: str = "https") -> str:
    return f"{scheme}://{host}/.well-known/redhive-verify.txt"


def verify_dns_txt(host: str, token: str) -> bool:
    """True if a TXT record at ``_redhive-verify.<host>`` contains the token."""
    try:
        import dns.resolver  # lazy import so the dep is optional at import time
    except ImportError:
        return False
    try:
        answers = dns.resolver.resolve(dns_record_name(host), "TXT", lifetime=5.0)
    except Exception:  # noqa: BLE001 — NXDOMAIN/timeout/etc. all mean "not verified"
        return False
    for rdata in answers:
        # TXT rdata is a sequence of byte strings; join and strip quotes.
        value = b"".join(getattr(rdata, "strings", [])).decode("utf-8", "ignore")
        if token in value:
            return True
    return False


def verify_http_file(host: str, token: str) -> bool:
    """True if the well-known file on the host contains the token (https→http)."""
    for scheme in ("https", "http"):
        try:
            resp = httpx.get(well_known_url(host, scheme=scheme), timeout=5.0, follow_redirects=True)
            if resp.status_code == 200 and token in resp.text:
                return True
        except httpx.HTTPError:
            continue
    return False


def check_ownership(host: str, token: str, method: str) -> bool:
    """Run the probe for the chosen method."""
    if method == "dns_txt":
        return verify_dns_txt(host, token)
    if method == "http_file":
        return verify_http_file(host, token)
    return False
