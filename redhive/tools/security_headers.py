"""Security-header auditor.

GETs a URL and inspects the response headers for the usual hardening
headers plus cookie flags, emitting one ``Finding`` per problem.
"""

from __future__ import annotations

import httpx

from redhive.models import Finding, Severity

_TIMEOUT = httpx.Timeout(8.0)
_HEADERS = {"User-Agent": "RedHive-Scanner/0.1 (+practice-app-only)"}

# header name -> (human title, severity, why it matters)
_REQUIRED_HEADERS: dict[str, tuple[str, Severity, str]] = {
    "Content-Security-Policy": (
        "Missing Content-Security-Policy header",
        Severity.MEDIUM,
        "A CSP restricts which resources can load, mitigating XSS and "
        "data-injection attacks.",
    ),
    "Strict-Transport-Security": (
        "Missing Strict-Transport-Security header",
        Severity.MEDIUM,
        "HSTS forces browsers to use HTTPS, preventing SSL-stripping "
        "downgrade attacks.",
    ),
    "X-Content-Type-Options": (
        "Missing X-Content-Type-Options header",
        Severity.LOW,
        "Without 'nosniff', browsers may MIME-sniff responses and execute "
        "unexpected content types.",
    ),
    "X-Frame-Options": (
        "Missing X-Frame-Options header",
        Severity.LOW,
        "Without framing protection the page can be embedded in an iframe "
        "for clickjacking.",
    ),
    "Referrer-Policy": (
        "Missing Referrer-Policy header",
        Severity.INFO,
        "A Referrer-Policy limits how much URL info leaks to third parties "
        "via the Referer header.",
    ),
}


def check_security_headers(url: str) -> list[Finding]:
    """Return findings for missing/weak security headers on ``url``.

    Also flags ``Set-Cookie`` values lacking HttpOnly/Secure/SameSite.
    Never raises: connection failures yield an empty list.
    """
    findings: list[Finding] = []

    try:
        with httpx.Client(
            timeout=_TIMEOUT,
            headers=_HEADERS,
            follow_redirects=True,
            verify=False,
        ) as client:
            resp = client.get(url)
    except httpx.HTTPError:
        return findings

    headers = resp.headers

    # --- Standard hardening headers -------------------------------------
    for name, (title, severity, why) in _REQUIRED_HEADERS.items():
        value = headers.get(name)
        if not value:
            findings.append(
                Finding(
                    title=title,
                    category="Security Headers",
                    severity=severity,
                    target=url,
                    description=why,
                    evidence=f"Response header '{name}' is not present.",
                    reproduction=[
                        f"Send: GET {url}",
                        f"Inspect response headers for '{name}'.",
                        "Observe the header is absent.",
                    ],
                    discovered_by="tools",
                )
            )

    # Weak/unsafe X-Content-Type-Options value.
    xcto = headers.get("X-Content-Type-Options")
    if xcto and xcto.strip().lower() != "nosniff":
        findings.append(
            Finding(
                title="Weak X-Content-Type-Options value",
                category="Security Headers",
                severity=Severity.LOW,
                target=url,
                description="X-Content-Type-Options should be exactly 'nosniff'.",
                evidence=f"X-Content-Type-Options: {xcto}",
                reproduction=[
                    f"Send: GET {url}",
                    "Inspect the X-Content-Type-Options header.",
                    f"Observe the non-'nosniff' value: {xcto}",
                ],
                discovered_by="tools",
            )
        )

    # --- Cookie flags ----------------------------------------------------
    # httpx exposes multiple Set-Cookie headers via get_list.
    set_cookies = headers.get_list("Set-Cookie")
    for cookie in set_cookies:
        lowered = cookie.lower()
        missing = [
            flag
            for flag, token in (
                ("HttpOnly", "httponly"),
                ("Secure", "secure"),
                ("SameSite", "samesite"),
            )
            if token not in lowered
        ]
        if missing:
            # Show only the cookie name=... prefix as evidence (no full value).
            snippet = cookie.split(";", 1)[0]
            findings.append(
                Finding(
                    title=f"Cookie missing flags: {', '.join(missing)}",
                    category="Security Headers",
                    severity=Severity.MEDIUM,
                    target=url,
                    description=(
                        "Session cookies should set HttpOnly (blocks JS access), "
                        "Secure (HTTPS only) and SameSite (CSRF mitigation)."
                    ),
                    evidence=f"Set-Cookie: {snippet}; (missing {', '.join(missing)})",
                    reproduction=[
                        f"Send: GET {url}",
                        "Inspect the Set-Cookie response header.",
                        f"Observe missing flag(s): {', '.join(missing)}.",
                    ],
                    discovered_by="tools",
                )
            )

    return findings
