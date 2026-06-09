"""Recon agent node.

The team's eyes. Crawls the target to map attack surface and fingerprints
the stack so the Lead has something concrete to reason over. Both tools fail
soft, so this node never crashes the engagement.
"""

from __future__ import annotations

from typing import Any

from redhive.models import EngagementState
from redhive.tools import crawl, fingerprint


def recon(state: EngagementState) -> dict[str, Any]:
    """Map attack surface (crawl) and fingerprint the stack.

    Writes serialized ``Endpoint`` dicts into ``attack_surface`` and stashes
    the fingerprint under ``attack_surface``-adjacent log lines.
    """
    target = state.get("target", "")
    log: list[str] = ["[recon] Crawling target to map attack surface..."]

    endpoints = crawl(target)
    surface = [ep.model_dump() for ep in endpoints]
    forms = sum(1 for ep in surface if ep.get("has_form"))
    log.append(
        f"[recon] Discovered {len(surface)} endpoint(s) "
        f"({forms} with forms)."
    )

    fp = fingerprint(target)
    techs = fp.get("technologies") or []
    server = fp.get("server") or "unknown"
    if techs:
        log.append(
            f"[recon] Fingerprint — server={server}, "
            f"tech={', '.join(techs)}."
        )
    else:
        log.append(f"[recon] Fingerprint — server={server}, no clear tech markers.")

    # Stash the fingerprint on state so the Lead can reason over it. We reuse
    # the scratchpad without changing the contract by tucking it under a
    # dedicated key the Lead reads (kept out of the EngagementState typeddict
    # to avoid contract churn — it's optional, total=False).
    return {
        "attack_surface": surface,
        "fingerprint": fp,  # type: ignore[typeddict-unknown-key]
        "log": log,
    }
