"""Cross-Site Request Forgery (CSRF) probe.

GETs a page, parses its forms with BeautifulSoup, and flags any
state-changing (POST) form that lacks an anti-CSRF token field and is not
backed by a SameSite session cookie. Purely heuristic and read-only --
nothing is submitted.
"""

from __future__ import annotations

import httpx
from bs4 import BeautifulSoup

from redhive.models import Finding, Severity

_TIMEOUT = httpx.Timeout(8.0)
_HEADERS = {"User-Agent": "RedHive-Scanner/0.1 (+practice-app-only)"}

# Substrings that, if present in an input's name/id, indicate a CSRF token.
_TOKEN_MARKERS = ("csrf", "token", "authenticity", "_token", "xsrf")


def _looks_like_token(name: str) -> bool:
    """True if a field name/id looks like an anti-CSRF token."""
    lowered = name.lower()
    return any(marker in lowered for marker in _TOKEN_MARKERS)


def check_csrf(url: str, params: list[str] | None = None) -> list[Finding]:
    """Probe ``url`` for forms lacking CSRF protection.

    Flags POST forms with no hidden anti-CSRF token field when the response
    also sets no SameSite cookie. ``params`` is accepted for signature
    parity with the other tools but is not required. Fails soft: a failed
    fetch or unparseable HTML yields an empty list.
    """
    findings: list[Finding] = []

    try:
        with httpx.Client(
            timeout=_TIMEOUT,
            headers=_HEADERS,
            follow_redirects=True,
            verify=False,  # practice apps often use self-signed / http
        ) as client:
            resp = client.get(url)
    except (httpx.HTTPError, ValueError):
        return findings

    # A SameSite cookie on the response provides baseline CSRF defense.
    cookie_blob = " ".join(resp.headers.get_list("Set-Cookie")).lower()
    has_samesite = "samesite" in cookie_blob

    try:
        soup = BeautifulSoup(resp.text or "", "html.parser")
        forms = soup.find_all("form")
    except Exception:
        # Defensive: never let a parser hiccup crash the scan.
        return findings

    for idx, form in enumerate(forms):
        method = (form.get("method") or "GET").strip().upper()
        if method != "POST":
            continue  # only state-changing forms are interesting

        # Gather every named/identified input on the form.
        field_names = []
        try:
            for el in form.find_all(["input", "textarea", "select"]):
                for attr in ("name", "id"):
                    val = el.get(attr)
                    if val:
                        field_names.append(val)
        except Exception:
            continue

        if any(_looks_like_token(n) for n in field_names):
            continue  # has a token-looking field -> assume protected
        if has_samesite:
            continue  # SameSite cookie provides defense-in-depth

        action = form.get("action") or url
        form_id = form.get("id") or form.get("name") or f"form #{idx + 1}"

        findings.append(
            Finding(
                title=f"POST form without CSRF protection ({form_id})",
                category="CSRF",
                severity=Severity.MEDIUM,
                target=url,
                description=(
                    "A state-changing POST form has no hidden anti-CSRF "
                    "token field and the response sets no SameSite cookie, "
                    "so a malicious site could forge this request on behalf "
                    "of an authenticated user."
                ),
                evidence=(
                    f"<form method=POST action={action!r}> with fields "
                    f"{field_names or '(none named)'}; no SameSite cookie set."
                ),
                reproduction=[
                    f"Send: GET {url}",
                    f"Locate the POST form ({form_id}).",
                    "Confirm it has no csrf/token/authenticity/_token/xsrf "
                    "field and no SameSite cookie defends it.",
                ],
                discovered_by="tools",
            )
        )

    return findings
