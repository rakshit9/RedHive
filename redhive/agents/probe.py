"""Parallel probe-agent swarm — the map-reduce heart of the engagement.

Instead of one node running every check sequentially, the Lead dispatches a
*swarm* of specialist probe agents that run concurrently:

    plan_probes ──(Send × N)──▶ probe ┐
                                probe ┤──▶ aggregate ──▶ validator
                                probe ┘
                                 ...(dozens, in parallel)

``plan_probes`` turns the attack surface into one task per (endpoint × check)
— e.g. an XSS agent for ``/search``, a headers agent for ``/login``, a TLS
agent for the host. ``fan_out_probes`` emits a LangGraph ``Send`` per task, so
they all execute in the same super-step. Each ``probe`` runs exactly one check
and appends its findings to the ``raw_findings`` channel (an ``operator.add``
reducer merges the concurrent writes). ``aggregate`` fans the results back in.

Real concurrency: probes are I/O-bound (HTTP + occasional LLM), and LangGraph
runs sync nodes on a thread pool, so a 40-agent fan-out genuinely overlaps
network waits. A module-level semaphore caps how many hit the target at once so
we stay a good neighbour (and within rate limits).
"""

from __future__ import annotations

import threading
from typing import Any

from langgraph.types import Send

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

# Cap concurrent probes actually touching the target (politeness + rate limits).
# The swarm can be far larger than this; the semaphore just bounds in-flight work.
MAX_CONCURRENT_PROBES = 12
_semaphore = threading.Semaphore(MAX_CONCURRENT_PROBES)

# Coverage caps — widened on a deep pass so round two genuinely digs further.
_MAX_ENDPOINTS = 8
_MAX_ENDPOINTS_DEEP = 20
_MAX_INPUTS = 8
_MAX_INPUTS_DEEP = 20

# Per-endpoint checks (run against every discovered URL).
_PER_ENDPOINT = ("headers", "cors")
# Per-input checks (run against endpoints that take params or have a form).
_PER_INPUT = ("xss", "sqli", "open_redirect", "csrf")
# Host-level checks (run once against the target).
_HOST_LEVEL = ("tls", "exposed_files", "outdated")

# Human-friendly names for the log so the swarm reads like a real team.
_AGENT_LABEL = {
    "headers": "HeadersAgent",
    "cors": "CORSAgent",
    "tls": "TLSAgent",
    "exposed_files": "ExposureAgent",
    "outdated": "CVEAgent",
    "xss": "XSSAgent",
    "sqli": "SQLiAgent",
    "open_redirect": "RedirectAgent",
    "csrf": "CSRFAgent",
}


def _endpoint_urls(state: EngagementState, limit: int) -> list[str]:
    target = state.get("target", "")
    urls: list[str] = [target] if target else []
    seen = set(urls)
    for ep in state.get("attack_surface", []):
        url = str(ep.get("url", ""))
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls[:limit]


def plan_probes(state: EngagementState) -> dict[str, Any]:
    """Expand the attack surface into the swarm's task list (the 'map' step)."""
    deep = bool(state.get("deep_pass"))
    ep_cap = _MAX_ENDPOINTS_DEEP if deep else _MAX_ENDPOINTS
    in_cap = _MAX_INPUTS_DEEP if deep else _MAX_INPUTS
    target = state.get("target", "")
    fp: dict[str, Any] = state.get("fingerprint", {})  # type: ignore[typeddict-item]

    tasks: list[dict[str, Any]] = []

    # Per-endpoint checks.
    urls = _endpoint_urls(state, ep_cap)
    for url in urls:
        for kind in _PER_ENDPOINT:
            tasks.append({"kind": kind, "url": url})

    # Host-level checks (once).
    if target:
        for kind in _HOST_LEVEL:
            tasks.append({"kind": kind, "url": target, "target": target, "fingerprint": fp})

    # Per-input checks on endpoints that accept input.
    inputs = [
        ep for ep in state.get("attack_surface", [])
        if ep.get("params") or ep.get("has_form")
    ][:in_cap]
    for ep in inputs:
        url = str(ep.get("url", ""))
        if not url:
            continue
        payload = {"url": url, "params": list(ep.get("params") or []), "method": str(ep.get("method", "GET"))}
        for kind in _PER_INPUT:
            tasks.append({"kind": kind, **payload})

    pass_label = "deep pass" if deep else "first pass"
    log = [
        f"[lead] Dispatching swarm ({pass_label}): {len(tasks)} specialist probe "
        f"agents across {len(urls)} endpoint(s) + {len(inputs)} input surface(s), "
        f"running in parallel (≤{MAX_CONCURRENT_PROBES} concurrent).",
    ]
    return {"probe_tasks": tasks, "agents_dispatched": len(tasks), "log": log}


def fan_out_probes(state: EngagementState) -> list[Send]:
    """Conditional edge: emit one ``Send`` per task so probes run concurrently."""
    return [Send("probe", task) for task in state.get("probe_tasks", [])]


def _run_check(task: dict[str, Any]) -> list[Any]:
    kind = task.get("kind")
    if kind == "headers":
        return check_security_headers(task["url"])
    if kind == "cors":
        return check_cors(task["url"])
    if kind == "tls":
        return check_tls(task["target"])
    if kind == "exposed_files":
        return check_exposed_files(task["target"])
    if kind == "outdated":
        return check_outdated(task.get("fingerprint", {}))
    if kind == "xss":
        return test_xss(task["url"], task.get("params", []), task.get("method", "GET"))
    if kind == "sqli":
        return test_sqli(task["url"], task.get("params", []), task.get("method", "GET"))
    if kind == "open_redirect":
        return check_open_redirect(task["url"], task.get("params", []))
    if kind == "csrf":
        return check_csrf(task["url"], task.get("params", []))
    return []


def probe(task: dict[str, Any]) -> dict[str, Any]:
    """One specialist agent: run a single check against a single surface.

    Receives its task as the node input (via ``Send``); appends any findings to
    the shared ``raw_findings`` channel. Bounded by the module semaphore so the
    swarm never overwhelms the target.
    """
    kind = str(task.get("kind", "?"))
    where = task.get("url") or task.get("target") or ""
    agent = _AGENT_LABEL.get(kind, kind)

    findings: list[dict[str, Any]] = []
    with _semaphore:
        try:
            for f in _run_check(task):
                findings.append(f.model_dump())
        except Exception:  # noqa: BLE001 — one probe must never sink the swarm
            return {"log": [f"[{agent}] error probing {where} — skipped."]}

    note = f"{len(findings)} finding(s)" if findings else "clean"
    return {"raw_findings": findings, "log": [f"[{agent}] {where} → {note}"]}


def aggregate(state: EngagementState) -> dict[str, Any]:
    """Fan-in (the 'reduce' step): collect the swarm's raw findings for the
    Validator. The Validator does the real de-duplication; here we just hand the
    accumulated raw set forward and report the swarm's throughput."""
    raw: list[dict[str, Any]] = state.get("raw_findings", [])
    dispatched = int(state.get("agents_dispatched", 0))
    log = [
        f"[aggregate] Swarm complete — {dispatched} probe agent(s) returned "
        f"{len(raw)} raw finding(s); handing off to the Validator."
    ]
    return {"findings": list(raw), "log": log}
