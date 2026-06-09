"""Open-redirect probe.

For each candidate redirect parameter, injects an off-host URL and checks
whether the response redirects the browser off the original host -- via a
3xx ``Location`` header, a ``<meta http-equiv=refresh>`` tag, or a simple
JavaScript ``location`` assignment.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import httpx

from redhive.models import Finding, Severity

_TIMEOUT = httpx.Timeout(8.0)
_HEADERS = {"User-Agent": "RedHive-Scanner/0.1 (+practice-app-only)"}

# Cap body inspection so a huge page can't dominate the scan.
_BODY_SCAN_LEN = 50_000

# The off-host payload we inject. Safe, non-destructive, clearly external.
_EVIL_HOST = "evil.example.com"
_PAYLOAD = f"https://{_EVIL_HOST}/"

# Params commonly used to carry a post-action redirect destination.
_COMMON_PARAMS = (
    "next",
    "url",
    "redirect",
    "return",
    "returnUrl",
    "dest",
    "continue",
)

# <meta http-equiv="refresh" content="0; url=...">
_META_REFRESH = re.compile(
    r"""<meta[^>]+http-equiv=['"]?refresh['"]?[^>]+url=['"]?([^'">\s]+)""",
    re.I,
)
# location = "...", location.href = "...", location.replace("...")
_JS_REDIRECT = re.compile(
    r"""location(?:\.href|\.replace\(|\s*=)\s*['"]([^'"]+)['"]""",
    re.I,
)


def _inject(url: str, param: str, value: str) -> str:
    """Return ``url`` with query ``param`` set to ``value`` (overwriting)."""
    parts = urlparse(url)
    query = parse_qs(parts.query, keep_blank_values=True)
    query[param] = [value]
    new_query = urlencode(query, doseq=True)
    return urlunparse(parts._replace(query=new_query))


def _off_host(origin: str, candidate: str) -> bool:
    """True if ``candidate`` resolves to a different host than ``origin``."""
    if not candidate:
        return False
    target = urljoin(origin, candidate)
    return urlparse(target).hostname == _EVIL_HOST


def check_open_redirect(
    url: str, params: list[str] | None = None
) -> list[Finding]:
    """Probe ``url`` for open redirects via candidate redirect params.

    For each param (the provided ``params`` else a common list) an off-host
    URL is injected and the response is inspected for a 3xx ``Location``, a
    meta-refresh, or a JS ``location`` assignment pointing off-host. Returns
    one ``Finding`` per vulnerable param. Never raises: per-probe failures
    are skipped.
    """
    findings: list[Finding] = []
    candidates = list(params) if params else list(_COMMON_PARAMS)

    try:
        # follow_redirects=False so we can observe the 3xx Location directly.
        client = httpx.Client(
            timeout=_TIMEOUT,
            headers=_HEADERS,
            follow_redirects=False,
            verify=False,  # practice apps often use self-signed / http
        )
    except httpx.HTTPError:
        return findings

    with client:
        for param in candidates:
            probe_url = _inject(url, param, _PAYLOAD)
            try:
                resp = client.get(probe_url)
            except (httpx.HTTPError, ValueError):
                continue  # one bad probe must never crash the scan

            vector = ""
            evidence = ""

            # --- 3xx Location header ------------------------------------
            if 300 <= resp.status_code < 400:
                location = resp.headers.get("Location", "")
                if _off_host(probe_url, location):
                    vector = "Location header"
                    evidence = (
                        f"GET {probe_url} -> {resp.status_code}; "
                        f"Location: {location}"
                    )

            # --- meta refresh / JS redirect in body ---------------------
            if not vector:
                ctype = resp.headers.get("content-type", "").lower()
                if "html" in ctype or not ctype:
                    body = (resp.text or "")[:_BODY_SCAN_LEN]
                    for label, pattern in (
                        ("meta refresh", _META_REFRESH),
                        ("JavaScript redirect", _JS_REDIRECT),
                    ):
                        m = pattern.search(body)
                        if m and _off_host(probe_url, m.group(1)):
                            vector = label
                            evidence = (
                                f"GET {probe_url} -> {resp.status_code}; "
                                f"{label}: {m.group(1)}"
                            )
                            break

            if not vector:
                continue

            findings.append(
                Finding(
                    title=f"Open redirect via '{param}' parameter",
                    category="Open Redirect",
                    severity=Severity.MEDIUM,
                    target=probe_url,
                    description=(
                        f"The '{param}' parameter is reflected into a redirect "
                        f"({vector}) without validation, letting an attacker "
                        "send victims to an arbitrary external site (phishing, "
                        "OAuth token theft)."
                    ),
                    evidence=evidence,
                    reproduction=[
                        f"Send: GET {probe_url}",
                        f"Observe the {vector} pointing to {_PAYLOAD}.",
                        "Confirm the browser is redirected off the original host.",
                    ],
                    discovered_by="tools",
                )
            )

    return findings
