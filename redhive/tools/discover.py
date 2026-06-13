"""Content/path discovery — the recon agent's second pair of eyes.

Crawling only finds what the app links to. Real pentesters also *probe* for
common paths (a la gobuster/dirb): login pages, admin panels, API routes,
config files, parameterized endpoints. ``discover_paths`` checks a curated
wordlist and returns an ``Endpoint`` for every path the server actually
handles (anything but a hard 404 / connection error), several carrying query
params so the injection agents have inputs to test.

This widens the attack surface, which means the parallel probe swarm fans out
to many more specialist agents on a real target. It is polite (bounded
concurrency, short timeout) and only ever runs against an in-scope host.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

from redhive.models import Endpoint

_TIMEOUT = httpx.Timeout(5.0)
_HEADERS = {"User-Agent": "RedHive-Scanner/0.1 (+practice-app-only)"}
_MAX_WORKERS = 10

# A path "exists" (is handled) if it returns anything other than a hard 404 or
# a transport error. 401/403/405 still reveal real surface worth probing.
_EXISTS = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500}

# Curated wordlist. Parameterized entries seed the injection/redirect agents.
_PATHS: tuple[str, ...] = (
    "/login", "/register", "/signup", "/admin", "/dashboard", "/account",
    "/profile", "/settings", "/users", "/user?id=1", "/profile?id=1",
    "/search?q=test", "/products?id=1", "/item?id=1", "/order?id=1",
    "/api", "/api/v1", "/api/users", "/api/login", "/api/products",
    "/api/search?q=test", "/graphql", "/docs", "/openapi.json", "/swagger",
    "/redirect?url=https://example.com", "/go?to=/", "/out?url=/",
    "/download?file=readme.txt", "/view?page=home", "/?lang=en",
    "/contact", "/feedback", "/upload", "/comment?text=hi",
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/health", "/status", "/metrics", "/debug", "/config",
)


def _params_of(url: str) -> list[str]:
    return sorted(parse_qs(urlparse(url).query).keys())


def _probe(client: httpx.Client, base: str, path: str) -> Endpoint | None:
    url = urljoin(base, path)
    try:
        resp = client.get(url)
    except httpx.HTTPError:
        return None
    if resp.status_code not in _EXISTS:
        return None
    params = _params_of(url)
    return Endpoint(
        url=url,
        method="GET",
        params=params,
        has_form=False,
        notes=f"discovered via path probe (HTTP {resp.status_code})",
    )


def discover_paths(target: str) -> list[Endpoint]:
    """Probe the wordlist against ``target`` and return live endpoints."""
    base = target if target.endswith("/") else target + "/"
    found: list[Endpoint] = []
    with httpx.Client(
        timeout=_TIMEOUT, headers=_HEADERS, follow_redirects=False, verify=False
    ) as client:
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = [pool.submit(_probe, client, base, p) for p in _PATHS]
            for fut in as_completed(futures):
                ep = fut.result()
                if ep is not None:
                    found.append(ep)
    return found
