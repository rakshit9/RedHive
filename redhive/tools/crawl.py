"""Lightweight, polite web crawler — the Recon agent's eyes.

Fetches a target with httpx, parses HTML with BeautifulSoup, and follows
same-host links (BFS) up to ``max_pages``. For every page it records the
URL, any <form> actions (with their method) and any query parameters as
``Endpoint`` objects the agents reason over later.
"""

from __future__ import annotations

from collections import deque
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from redhive.models import Endpoint

# Be polite: short timeout, identifiable UA, and a sane page cap.
_TIMEOUT = httpx.Timeout(8.0)
_HEADERS = {"User-Agent": "RedHive-Scanner/0.1 (+practice-app-only)"}


def _same_host(a: str, b: str) -> bool:
    """True if two URLs share the same (case-insensitive) hostname."""
    return urlparse(a).hostname == urlparse(b).hostname


def _params_of(url: str) -> list[str]:
    """Return the sorted list of query-param names present in ``url``."""
    return sorted(parse_qs(urlparse(url).query).keys())


def crawl(target: str, max_pages: int = 25) -> list[Endpoint]:
    """Crawl ``target`` and return discovered attack surface.

    Follows same-host links breadth-first, collecting page URLs, <form>
    actions (``has_form=True`` + the form's method), and query params.
    Never raises: a failing fetch just skips that page.
    """
    seen_pages: set[str] = set()
    endpoints: dict[tuple[str, str], Endpoint] = {}  # dedupe by (url, method)
    queue: deque[str] = deque([target])

    def _add(url: str, method: str = "GET", *, has_form: bool = False,
             extra_params: list[str] | None = None, notes: str = "") -> None:
        key = (url, method.upper())
        if key not in endpoints:
            # Merge query-string params with any form-field names so the
            # injection probes know exactly what inputs to test.
            params = sorted(set(_params_of(url)) | set(extra_params or []))
            endpoints[key] = Endpoint(
                url=url,
                method=method.upper(),
                params=params,
                has_form=has_form,
                notes=notes,
            )

    with httpx.Client(
        timeout=_TIMEOUT,
        headers=_HEADERS,
        follow_redirects=True,
        verify=False,  # practice apps often use self-signed / http
    ) as client:
        while queue and len(seen_pages) < max_pages:
            url = queue.popleft()
            if url in seen_pages:
                continue
            seen_pages.add(url)

            try:
                resp = client.get(url)
            except (httpx.HTTPError, ValueError):
                # Network hiccup / malformed URL — skip, never crash the scan.
                continue

            # Record the page itself as an endpoint.
            _add(url, "GET")

            ctype = resp.headers.get("content-type", "")
            if "html" not in ctype.lower():
                continue  # nothing to parse on non-HTML responses

            soup = BeautifulSoup(resp.text, "html.parser")

            # Forms become endpoints carrying their declared method.
            for form in soup.find_all("form"):
                action = form.get("action") or url
                form_url = urljoin(url, action)
                method = (form.get("method") or "GET").upper()
                # Collect named inputs so the injection probes have fields to test.
                fields = [
                    el.get("name")
                    for el in form.find_all(["input", "textarea", "select"])
                    if el.get("name")
                ]
                if _same_host(target, form_url):
                    _add(form_url, method, has_form=True,
                         extra_params=fields, notes="discovered via <form>")

            # Queue same-host anchor links for further crawling.
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])
                # Drop fragments so #anchors don't create phantom pages.
                link, _, _ = link.partition("#")
                if not link or not link.startswith(("http://", "https://")):
                    continue
                if _same_host(target, link) and link not in seen_pages:
                    queue.append(link)
                    _add(link, "GET")

    return list(endpoints.values())
