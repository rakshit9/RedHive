"""Reflected-XSS and error-based SQL-injection probes.

Safe, signature-based checks for AUTHORIZED PRACTICE TARGETS ONLY:

- ``test_xss`` injects a unique, non-executing marker into each input and
  flags the parameter if the marker is reflected back unescaped.
- ``test_sqli`` injects a benign quote-breaking payload and flags the
  parameter if the response contains a known database error signature.

Neither attempts real exploitation — they only detect the *signal* that a
vulnerability exists, which is enough for triage and keeps the tool safe.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx

from redhive.models import Finding, Severity

_TIMEOUT = httpx.Timeout(8.0)
_HEADERS = {"User-Agent": "RedHive-Scanner/0.1 (+practice-app-only)"}

# A unique, non-executing marker that is unlikely to occur naturally but is
# trivial to detect if reflected. We do NOT inject a working script.
_XSS_MARKER = "rh7xZmark9q"
_XSS_PAYLOAD = f"<{_XSS_MARKER}>"

# A minimal payload that breaks naive SQL string handling.
_SQLI_PAYLOAD = "1'\""

# Common SQL error signatures across engines (lower-cased).
_SQL_ERROR_SIGNATURES = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sqlite3.operationalerror",
    "sqlite error",
    "psycopg2",
    "syntax error at or near",
    "pg::syntaxerror",
    "ora-00933",
    "ora-01756",
    "odbc sql server driver",
    "sqlstate",
    "mysqli_sql_exception",
)


def _fields_for(url: str, params: list[str] | None) -> list[str]:
    """Inputs to test: explicit params, else names parsed from the query string."""
    if params:
        return [p for p in params if p]
    return sorted(parse_qs(urlparse(url).query).keys())


def _send(client: httpx.Client, url: str, method: str, data: dict[str, str]):
    """Send one request, GET via query params or POST via form body."""
    if method.upper() == "POST":
        return client.post(url, data=data)
    return client.get(url, params=data)


def test_xss(
    url: str, params: list[str] | None = None, method: str = "GET"
) -> list[Finding]:
    """Probe each input on ``url`` for reflected XSS (marker reflected unescaped)."""
    findings: list[Finding] = []
    fields = _fields_for(url, params)
    if not fields:
        return findings

    try:
        client = httpx.Client(
            timeout=_TIMEOUT, headers=_HEADERS, follow_redirects=True, verify=False
        )
    except httpx.HTTPError:
        return findings

    with client:
        for field in fields:
            data = {f: "test" for f in fields}
            data[field] = _XSS_PAYLOAD
            try:
                resp = _send(client, url, method, data)
            except (httpx.HTTPError, ValueError):
                continue  # one bad probe must never crash the scan

            # Reflected verbatim (not HTML-encoded) => likely XSS.
            if _XSS_PAYLOAD in (resp.text or ""):
                findings.append(
                    Finding(
                        title=f"Reflected XSS in parameter '{field}'",
                        category="XSS",
                        severity=Severity.HIGH,
                        target=url,
                        description=(
                            "User input is reflected in the response without "
                            "output encoding, allowing reflected cross-site "
                            "scripting."
                        ),
                        evidence=(
                            f"Injected {_XSS_PAYLOAD!r} into '{field}' "
                            f"({method.upper()}); the marker was reflected "
                            "unescaped in the response body."
                        ),
                        reproduction=[
                            f"Send {method.upper()} {url} with {field}={_XSS_PAYLOAD}",
                            "Observe the payload reflected unencoded in the HTML.",
                            "Swap the marker for a real script payload to confirm execution.",
                        ],
                        discovered_by="tools",
                    )
                )
    return findings


def test_sqli(
    url: str, params: list[str] | None = None, method: str = "GET"
) -> list[Finding]:
    """Probe each input on ``url`` for error-based SQL injection."""
    findings: list[Finding] = []
    fields = _fields_for(url, params)
    if not fields:
        return findings

    try:
        client = httpx.Client(
            timeout=_TIMEOUT, headers=_HEADERS, follow_redirects=True, verify=False
        )
    except httpx.HTTPError:
        return findings

    with client:
        for field in fields:
            data = {f: "1" for f in fields}
            data[field] = _SQLI_PAYLOAD
            try:
                resp = _send(client, url, method, data)
            except (httpx.HTTPError, ValueError):
                continue

            body = (resp.text or "").lower()
            hit = next((s for s in _SQL_ERROR_SIGNATURES if s in body), None)
            if hit:
                findings.append(
                    Finding(
                        title=f"Possible SQL injection in parameter '{field}'",
                        category="SQLi",
                        severity=Severity.HIGH,
                        target=url,
                        description=(
                            "Injecting a quote produced a database error, "
                            "indicating input is concatenated into a SQL query "
                            "without parameterization."
                        ),
                        evidence=(
                            f"Injected {_SQLI_PAYLOAD!r} into '{field}' "
                            f"({method.upper()}); response contained SQL error "
                            f"signature: {hit!r}."
                        ),
                        reproduction=[
                            f"Send {method.upper()} {url} with {field}={_SQLI_PAYLOAD}",
                            "Observe the database error in the response.",
                            "Confirm with a boolean/time-based payload before exploitation.",
                        ],
                        discovered_by="tools",
                    )
                )
    return findings
