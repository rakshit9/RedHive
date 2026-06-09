"""Lightweight technology fingerprinter.

GETs a URL and guesses the running server / framework / libraries from
response headers and a few telltale body markers. Returns plain data
(no ``Finding``) for other agents to reason over.
"""

from __future__ import annotations

import re

import httpx

_TIMEOUT = httpx.Timeout(8.0)
_HEADERS = {"User-Agent": "RedHive-Scanner/0.1 (+practice-app-only)"}

# Cap body inspection so a huge page can't dominate the scan.
_BODY_SCAN_LEN = 50_000

# Header name -> technology label. The header's mere presence is the signal.
_HEADER_TECH: dict[str, str] = {
    "X-AspNet-Version": "ASP.NET",
    "X-AspNetMvc-Version": "ASP.NET MVC",
    "X-Drupal-Cache": "Drupal",
    "X-Generator": "X-Generator",
    "X-Shopify-Stage": "Shopify",
    "X-Magento-Cache-Debug": "Magento",
}

# Regexes matched against header values / body to guess technologies.
_BODY_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("WordPress", re.compile(r"/wp-(content|includes)/", re.I)),
    ("Drupal", re.compile(r"(Drupal\.settings|/sites/(default|all)/)", re.I)),
    ("Joomla", re.compile(r"/media/jui/|com_content", re.I)),
    ("React", re.compile(r"\bdata-reactroot\b|__REACT_DEVTOOLS", re.I)),
    ("Vue.js", re.compile(r"\bdata-v-[0-9a-f]{8}\b|__VUE__", re.I)),
    ("Angular", re.compile(r"\bng-version\b|ng-app", re.I)),
    ("jQuery", re.compile(r"jquery(\.min)?\.js", re.I)),
    ("Bootstrap", re.compile(r"bootstrap(\.min)?\.(css|js)", re.I)),
    ("Express", re.compile(r"\bExpress\b", re.I)),
    ("Laravel", re.compile(r"laravel_session|XSRF-TOKEN", re.I)),
)


def fingerprint(url: str) -> dict:
    """Fingerprint ``url`` and return server/framework/technology hints.

    Always returns a dict with keys ``server``, ``x_powered_by`` and
    ``technologies`` (a de-duplicated list). Never raises: on failure the
    fields are ``None`` / empty.
    """
    result: dict = {"server": None, "x_powered_by": None, "technologies": []}

    try:
        with httpx.Client(
            timeout=_TIMEOUT,
            headers=_HEADERS,
            follow_redirects=True,
            verify=False,  # practice apps often use self-signed / http
        ) as client:
            resp = client.get(url)
    except (httpx.HTTPError, ValueError):
        return result

    headers = resp.headers
    result["server"] = headers.get("Server")
    result["x_powered_by"] = headers.get("X-Powered-By")

    techs: list[str] = []

    def _add(tech: str | None) -> None:
        if tech and tech not in techs:
            techs.append(tech)

    # Direct hints from header values.
    _add(result["server"])
    _add(result["x_powered_by"])
    _add(headers.get("X-Generator"))

    # Presence-based header signatures.
    for header_name, label in _HEADER_TECH.items():
        if header_name in headers:
            _add(label)

    # Cookie-name heuristics.
    cookie_blob = " ".join(headers.get_list("Set-Cookie")).lower()
    if "phpsessid" in cookie_blob:
        _add("PHP")
    if "asp.net_sessionid" in cookie_blob:
        _add("ASP.NET")
    if "jsessionid" in cookie_blob:
        _add("Java")

    # Body signatures (only inspect HTML, only the first chunk).
    ctype = headers.get("content-type", "").lower()
    if "html" in ctype:
        body = (resp.text or "")[:_BODY_SCAN_LEN]
        for label, pattern in _BODY_SIGNATURES:
            if pattern.search(body):
                _add(label)

    result["technologies"] = techs
    return result
