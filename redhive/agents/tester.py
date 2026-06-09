"""Test agent node.

Runs the deterministic probes — security headers, TLS, exposed files — across
the target and the discovered endpoints, collecting raw ``Finding`` objects.
Every tool fails soft, so a dead host simply yields fewer findings rather than
crashing the engagement.
"""

from __future__ import annotations

from typing import Any

from redhive.models import EngagementState
from redhive.tools import (
    check_exposed_files,
    check_security_headers,
    check_tls,
    test_sqli,
    test_xss,
)

# Cap how many distinct URLs we header-scan so a big crawl can't explode runtime.
_MAX_HEADER_TARGETS = 10
# Cap how many input-bearing endpoints we fuzz with injection probes.
_MAX_INJECTION_TARGETS = 10


def _scan_targets(state: EngagementState) -> list[str]:
    """The target plus a deduped sample of discovered endpoint URLs."""
    target = state.get("target", "")
    urls: list[str] = [target] if target else []
    seen = set(urls)
    for ep in state.get("attack_surface", []):
        url = str(ep.get("url", ""))
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls[:_MAX_HEADER_TARGETS]


def tester(state: EngagementState) -> dict[str, Any]:
    """Run header/TLS/exposed-file probes and collect raw findings."""
    target = state.get("target", "")
    log: list[str] = ["[tester] Running selected probes..."]

    findings: list[dict[str, Any]] = []

    # Security headers + cookie flags across the sampled endpoints.
    header_targets = _scan_targets(state)
    for url in header_targets:
        for f in check_security_headers(url):
            findings.append(f.model_dump())
    log.append(
        f"[tester] Security-header scan over {len(header_targets)} endpoint(s)."
    )

    # TLS posture — host-level, so only the target once.
    if target:
        tls_findings = check_tls(target)
        for f in tls_findings:
            findings.append(f.model_dump())
        log.append(f"[tester] TLS scan produced {len(tls_findings)} finding(s).")

        # Exposed sensitive files — relative to the target root.
        exposed = check_exposed_files(target)
        for f in exposed:
            findings.append(f.model_dump())
        log.append(f"[tester] Exposed-file scan produced {len(exposed)} finding(s).")

    # Injection probes (reflected XSS, error-based SQLi) against every endpoint
    # that actually takes input — a query param or a discovered form.
    injection_targets = [
        ep
        for ep in state.get("attack_surface", [])
        if ep.get("params") or ep.get("has_form")
    ][:_MAX_INJECTION_TARGETS]
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
    log.append(
        f"[tester] Injection probes over {len(injection_targets)} input(s) "
        f"produced {injected} finding(s)."
    )

    log.append(f"[tester] Collected {len(findings)} raw finding(s) total.")
    return {"findings": findings, "log": log}
