"""Test agent node.

Runs the probes the Lead selected across the target and discovered endpoints,
collecting raw ``Finding`` objects. Every tool fails soft, so a dead host
simply yields fewer findings rather than crashing the engagement.

The node is re-entrant: on a deeper pass (``state["deep_pass"]`` set by the
Lead's review) it widens coverage — more endpoints, all input probes — so the
second round genuinely digs further rather than repeating the first.
"""

from __future__ import annotations

from typing import Any

from redhive.models import EngagementState
from redhive.tools import (
    check_cors,
    check_csrf,
    check_exposed_files,
    check_open_redirect,
    check_outdated,
    check_security_headers,
    check_tls,
    test_sqli,
    test_xss,
)

# Coverage caps — widened on a deep pass so the second round digs further.
_MAX_HEADER_TARGETS = 10
_MAX_HEADER_TARGETS_DEEP = 25
_MAX_INJECTION_TARGETS = 10
_MAX_INJECTION_TARGETS_DEEP = 25


def _endpoint_urls(state: EngagementState, limit: int) -> list[str]:
    """The target plus a deduped sample of discovered endpoint URLs."""
    target = state.get("target", "")
    urls: list[str] = [target] if target else []
    seen = set(urls)
    for ep in state.get("attack_surface", []):
        url = str(ep.get("url", ""))
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls[:limit]


def tester(state: EngagementState) -> dict[str, Any]:
    """Run the selected probes and collect raw findings."""
    target = state.get("target", "")
    deep = bool(state.get("deep_pass"))
    pass_label = "deep pass" if deep else "first pass"
    log: list[str] = [f"[tester] Running probes ({pass_label})..."]

    header_cap = _MAX_HEADER_TARGETS_DEEP if deep else _MAX_HEADER_TARGETS
    inj_cap = _MAX_INJECTION_TARGETS_DEEP if deep else _MAX_INJECTION_TARGETS

    findings: list[dict[str, Any]] = []

    # --- Server-wide / per-endpoint header checks ------------------------
    header_targets = _endpoint_urls(state, header_cap)
    for url in header_targets:
        for f in check_security_headers(url):
            findings.append(f.model_dump())
        for f in check_cors(url):
            findings.append(f.model_dump())
    log.append(f"[tester] Header/CORS scan over {len(header_targets)} endpoint(s).")

    # --- Host-level checks (once) ----------------------------------------
    if target:
        for f in check_tls(target):
            findings.append(f.model_dump())
        for f in check_exposed_files(target):
            findings.append(f.model_dump())
        # Outdated-software check reads the recon fingerprint off state.
        fp: dict[str, Any] = state.get("fingerprint", {})  # type: ignore[typeddict-item]
        for f in check_outdated(fp):
            findings.append(f.model_dump())
        log.append("[tester] TLS / exposed-file / outdated-software scan done.")

    # --- Input-bearing endpoints: injection + redirect + CSRF -------------
    injection_targets = [
        ep
        for ep in state.get("attack_surface", [])
        if ep.get("params") or ep.get("has_form")
    ][:inj_cap]
    injected = 0
    for ep in injection_targets:
        url = str(ep.get("url", ""))
        if not url:
            continue
        params = list(ep.get("params") or [])
        method = str(ep.get("method", "GET"))
        for f in test_xss(url, params, method):
            findings.append(f.model_dump())
            injected += 1
        for f in test_sqli(url, params, method):
            findings.append(f.model_dump())
            injected += 1
        for f in check_open_redirect(url, params):
            findings.append(f.model_dump())
            injected += 1
        for f in check_csrf(url, params):
            findings.append(f.model_dump())
            injected += 1
    log.append(
        f"[tester] Injection/redirect/CSRF over {len(injection_targets)} input(s) "
        f"produced {injected} finding(s)."
    )

    log.append(f"[tester] Collected {len(findings)} raw finding(s) total.")
    return {"findings": findings, "log": log}
