"""Orchestrator (Manager) node.

The first node in the graph and the safety chokepoint. It runs the scope
guard before any packet leaves the box: if the target is out of scope it
refuses the engagement and ends the run. Otherwise it sets an initial plan
and hands off to the Recon agent.
"""

from __future__ import annotations

from typing import Any

from redhive.models import EngagementState
from redhive.scope import ScopeError, assert_allowed


def orchestrator(state: EngagementState) -> dict[str, Any]:
    """Gate the engagement on scope, then set the initial plan.

    Sets ``scope_allowed``. On a ScopeError it sets ``done=True`` and logs a
    refusal so the conditional edge can short-circuit to END.
    """
    target = state.get("target", "")
    log: list[str] = [f"[manager] Engagement requested for target: {target!r}"]

    try:
        assert_allowed(target)
    except ScopeError as exc:
        log.append(f"[manager] REFUSED — target is out of scope: {exc}")
        return {"scope_allowed": False, "done": True, "log": log}

    log.append("[manager] Scope check passed — target is authorized.")
    plan = [
        "Recon: map the attack surface (crawl + fingerprint).",
        "Lead: reason over recon output and pick the tests that matter.",
        "Tester: run the selected probes and collect raw findings.",
        "Validator: re-check findings and confirm the real ones.",
        "Reporter: write remediation and a final summary.",
    ]
    log.append("[manager] Initial plan set; dispatching the Recon agent.")
    return {"scope_allowed": True, "plan": plan, "log": log}
