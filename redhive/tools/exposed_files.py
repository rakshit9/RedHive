"""Sensitive-file & directory-listing probe.

Requests a small set of well-known sensitive paths relative to the target
and emits a ``Finding`` whenever one returns HTTP 200 with plausible
content. Also detects classic auto-generated directory listings.
"""

from __future__ import annotations

from urllib.parse import urljoin

import httpx

from redhive.models import Finding, Severity

_TIMEOUT = httpx.Timeout(8.0)
_HEADERS = {"User-Agent": "RedHive-Scanner/0.1 (+practice-app-only)"}

# Cap how much body we read/snippet so a huge response can't blow up memory.
_SNIPPET_LEN = 200

# path -> (human title, severity, why it matters, substrings that confirm
# the response really is the sensitive file -- empty tuple = accept any 200)
_SENSITIVE_PATHS: dict[str, tuple[str, Severity, str, tuple[str, ...]]] = {
    "/.git/config": (
        "Exposed Git config (.git/config)",
        Severity.HIGH,
        "An exposed .git directory can leak full source history, secrets "
        "and credentials.",
        ("[core]", "repositoryformatversion"),
    ),
    "/.git/HEAD": (
        "Exposed Git HEAD (.git/HEAD)",
        Severity.HIGH,
        "A reachable .git/HEAD confirms the .git directory is web-served, "
        "allowing source-tree reconstruction.",
        ("ref:", "refs/"),
    ),
    "/.env": (
        "Exposed environment file (.env)",
        Severity.HIGH,
        "An exposed .env typically contains API keys, DB credentials and "
        "other secrets.",
        ("=",),
    ),
    "/backup.zip": (
        "Exposed backup archive (backup.zip)",
        Severity.HIGH,
        "A publicly downloadable backup archive can leak source code, "
        "databases and credentials.",
        (),
    ),
    "/.DS_Store": (
        "Exposed .DS_Store file",
        Severity.LOW,
        "A served .DS_Store leaks directory and file names, aiding "
        "further enumeration.",
        (),
    ),
    "/robots.txt": (
        "robots.txt is present",
        Severity.INFO,
        "robots.txt is informational; it may reveal hidden or "
        "administrative paths worth reviewing.",
        (),
    ),
}

# Markers that a 200 HTML response is an auto-generated directory listing.
_DIR_LISTING_MARKERS = (
    "index of /",
    "<title>directory listing for",
    "[to parent directory]",
)


def _confirms(body: str, markers: tuple[str, ...]) -> bool:
    """True if ``body`` contains any confirming marker (or none required)."""
    if not markers:
        return True
    lowered = body.lower()
    return any(m.lower() in lowered for m in markers)


def check_exposed_files(url: str) -> list[Finding]:
    """Probe ``url`` for common sensitive files and directory listings.

    Returns one ``Finding`` per exposed path (HTTP 200 with plausible
    content). Never raises: per-probe failures are skipped, and a dead
    target yields an empty list.
    """
    findings: list[Finding] = []

    try:
        client = httpx.Client(
            timeout=_TIMEOUT,
            headers=_HEADERS,
            follow_redirects=True,
            verify=False,  # practice apps often use self-signed / http
        )
    except httpx.HTTPError:
        return findings

    with client:
        # --- Known sensitive paths --------------------------------------
        for path, (title, severity, why, markers) in _SENSITIVE_PATHS.items():
            probe_url = urljoin(url, path)
            try:
                resp = client.get(probe_url)
            except (httpx.HTTPError, ValueError):
                continue  # one bad probe must never crash the scan

            if resp.status_code != 200:
                continue

            body = resp.text or ""
            if not _confirms(body, markers):
                continue

            snippet = body[:_SNIPPET_LEN].replace("\n", " ").strip()
            findings.append(
                Finding(
                    title=title,
                    category="Exposed File",
                    severity=severity,
                    target=probe_url,
                    description=why,
                    evidence=(
                        f"GET {probe_url} -> {resp.status_code} "
                        f"({len(body)} bytes). Snippet: {snippet!r}"
                    ),
                    reproduction=[
                        f"Send: GET {probe_url}",
                        "Observe the HTTP 200 response.",
                        "Confirm the body contains the sensitive content above.",
                    ],
                    discovered_by="tools",
                )
            )

        # --- Directory listing detection --------------------------------
        try:
            resp = client.get(url)
        except (httpx.HTTPError, ValueError):
            resp = None

        if resp is not None and resp.status_code == 200:
            body = resp.text or ""
            lowered = body.lower()
            if any(marker in lowered for marker in _DIR_LISTING_MARKERS):
                snippet = body[:_SNIPPET_LEN].replace("\n", " ").strip()
                findings.append(
                    Finding(
                        title="Directory listing enabled",
                        category="Exposed File",
                        severity=Severity.MEDIUM,
                        target=url,
                        description=(
                            "The server returns an auto-generated directory "
                            "listing, exposing file names that aid enumeration."
                        ),
                        evidence=(
                            f"GET {url} -> {resp.status_code}. "
                            f"Listing snippet: {snippet!r}"
                        ),
                        reproduction=[
                            f"Send: GET {url}",
                            "Observe the HTTP 200 response.",
                            "Confirm the body is an auto-generated directory listing.",
                        ],
                        discovered_by="tools",
                    )
                )

    return findings
