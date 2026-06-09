"""TLS / certificate inspector using only the stdlib ``ssl`` module.

Connects to the host on 443, then checks certificate expiry and the
negotiated TLS protocol version. Designed to fail soft: plain-HTTP or
localhost practice apps without TLS return an empty list, not a crash.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from redhive.models import Finding, Severity

_PORT = 443
_TIMEOUT = 8.0
# Warn when a cert expires within this many days.
_EXPIRY_WARN_DAYS = 30

# Map ssl protocol strings to a comparable (major, minor) tuple.
_TLS_VERSIONS = {
    "SSLv3": (3, 0),
    "TLSv1": (1, 0),
    "TLSv1.1": (1, 1),
    "TLSv1.2": (1, 2),
    "TLSv1.3": (1, 3),
}


def _clean_host(host: str) -> str:
    """Strip scheme/path/port so callers can pass a URL or bare host."""
    if "://" in host:
        host = urlparse(host).hostname or host
    else:
        host = host.split("/", 1)[0].split(":", 1)[0]
    return host.strip()


def check_tls(host: str) -> list[Finding]:
    """Return findings about the TLS posture of ``host`` on port 443.

    Flags expired/expiring certs and TLS versions below 1.2. Hosts that
    don't speak TLS (e.g. http-only localhost) yield ``[]`` gracefully.
    """
    findings: list[Finding] = []
    hostname = _clean_host(host)
    if not hostname:
        return findings

    ctx = ssl.create_default_context()
    # Practice apps often use self-signed certs; we still want to read the
    # cert + protocol, so relax verification (this is a scanner, not a client).
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, _PORT), timeout=_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                version = ssock.version()  # e.g. "TLSv1.3"
                cert = ssock.getpeercert()
    except (OSError, ssl.SSLError, ValueError):
        # No TLS listener / refused / timeout — not applicable, return [].
        return findings

    # --- TLS protocol version -------------------------------------------
    if version:
        ver_tuple = _TLS_VERSIONS.get(version, (9, 9))  # unknown -> treat as new
        if ver_tuple < (1, 2):
            findings.append(
                Finding(
                    title=f"Outdated TLS version negotiated: {version}",
                    category="TLS",
                    severity=Severity.HIGH,
                    target=hostname,
                    description=(
                        "TLS versions below 1.2 are deprecated and vulnerable "
                        "to known downgrade and cipher attacks."
                    ),
                    evidence=f"Negotiated protocol: {version}",
                    reproduction=[
                        f"Connect: openssl s_client -connect {hostname}:{_PORT}",
                        f"Observe negotiated protocol {version} (< TLS 1.2).",
                    ],
                    discovered_by="tools",
                )
            )

    # --- Certificate expiry ---------------------------------------------
    # cert may be {} when CERT_NONE is set; only check if we got fields.
    not_after = cert.get("notAfter") if cert else None
    if not_after:
        try:
            # Format: 'Jun  1 12:00:00 2026 GMT'
            expires = datetime.strptime(
                not_after, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            expires = None

        if expires:
            now = datetime.now(timezone.utc)
            days_left = (expires - now).days
            if expires < now:
                findings.append(
                    Finding(
                        title="TLS certificate is expired",
                        category="TLS",
                        severity=Severity.HIGH,
                        target=hostname,
                        description="The server's certificate has already expired.",
                        evidence=f"notAfter={not_after} (expired {-days_left} days ago)",
                        reproduction=[
                            f"Connect to {hostname}:{_PORT} and read the certificate.",
                            f"Observe notAfter={not_after} is in the past.",
                        ],
                        discovered_by="tools",
                    )
                )
            elif days_left <= _EXPIRY_WARN_DAYS:
                findings.append(
                    Finding(
                        title="TLS certificate expiring soon",
                        category="TLS",
                        severity=Severity.LOW,
                        target=hostname,
                        description=(
                            f"The certificate expires in {days_left} days; renew "
                            "before it lapses to avoid an outage."
                        ),
                        evidence=f"notAfter={not_after} ({days_left} days remaining)",
                        reproduction=[
                            f"Connect to {hostname}:{_PORT} and read the certificate.",
                            f"Observe notAfter={not_after} is within {_EXPIRY_WARN_DAYS} days.",
                        ],
                        discovered_by="tools",
                    )
                )

    return findings
