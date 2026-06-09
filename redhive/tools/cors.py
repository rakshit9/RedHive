"""CORS misconfiguration probe.

Sends a request carrying an arbitrary ``Origin`` and inspects the
``Access-Control-Allow-Origin`` / ``Access-Control-Allow-Credentials``
response headers for the classic over-permissive patterns: reflecting an
attacker-controlled origin, or ``*`` together with credentials.
"""

from __future__ import annotations

import httpx

from redhive.models import Finding, Severity

_TIMEOUT = httpx.Timeout(8.0)
_HEADERS = {"User-Agent": "RedHive-Scanner/0.1 (+practice-app-only)"}

# The arbitrary, attacker-controlled origin we present.
_EVIL_ORIGIN = "https://evil.example.com"


def check_cors(url: str) -> list[Finding]:
    """Probe ``url`` for a permissive CORS policy.

    Issues a GET with ``Origin: https://evil.example.com`` and flags the
    response when ``Access-Control-Allow-Origin`` reflects that origin, or
    is ``*`` while credentials are allowed. Severity is HIGH when the
    arbitrary origin is reflected with credentials, otherwise MEDIUM.
    Never raises: a failed request yields an empty list.
    """
    findings: list[Finding] = []

    try:
        with httpx.Client(
            timeout=_TIMEOUT,
            headers=_HEADERS,
            follow_redirects=True,
            verify=False,  # practice apps often use self-signed / http
        ) as client:
            resp = client.get(url, headers={"Origin": _EVIL_ORIGIN})
    except (httpx.HTTPError, ValueError):
        return findings

    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
    creds = acac.strip().lower() == "true"

    if not acao:
        return findings

    acao_stripped = acao.strip()
    reflected = acao_stripped == _EVIL_ORIGIN
    wildcard = acao_stripped == "*"

    title = ""
    severity = Severity.MEDIUM
    description = ""

    if reflected:
        # Server echoes whatever Origin it is sent -> any site can read responses.
        severity = Severity.HIGH if creds else Severity.MEDIUM
        title = "CORS reflects arbitrary Origin"
        description = (
            "The server reflects the request's Origin into "
            "Access-Control-Allow-Origin, so any website can issue "
            "cross-origin requests and read the responses."
        )
        if creds:
            description += (
                " Because Access-Control-Allow-Credentials is true, an "
                "attacker site can read authenticated, credentialed responses."
            )
    elif wildcard and creds:
        # '*' + credentials is invalid per spec but some stacks honor it.
        severity = Severity.MEDIUM
        title = "CORS wildcard with credentials"
        description = (
            "Access-Control-Allow-Origin is '*' while "
            "Access-Control-Allow-Credentials is true. This combination is "
            "unsafe (and spec-invalid) and may expose credentialed data."
        )
    else:
        return findings

    findings.append(
        Finding(
            title=title,
            category="CORS",
            severity=severity,
            target=url,
            description=description,
            evidence=(
                f"Request Origin: {_EVIL_ORIGIN}; "
                f"Access-Control-Allow-Origin: {acao_stripped}; "
                f"Access-Control-Allow-Credentials: {acac or '(absent)'}"
            ),
            reproduction=[
                f"Send: GET {url} with header 'Origin: {_EVIL_ORIGIN}'",
                "Inspect the Access-Control-Allow-Origin response header.",
                f"Observe it returns '{acao_stripped}' "
                f"(credentials: {acac or 'absent'}).",
            ],
            discovered_by="tools",
        )
    )

    return findings
