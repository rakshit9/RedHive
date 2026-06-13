"""Recon agent node.

The team's eyes. Crawls the target to map attack surface and fingerprints
the stack so the Lead has something concrete to reason over. Both tools fail
soft, so this node never crashes the engagement.
"""

from __future__ import annotations

from typing import Any

from redhive.models import EngagementState
from redhive.tools import crawl, discover_paths, fingerprint


def recon(state: EngagementState) -> dict[str, Any]:
    """Map attack surface (crawl + path discovery) and fingerprint the stack.

    Writes serialized ``Endpoint`` dicts into ``attack_surface`` and stashes
    the fingerprint under ``attack_surface``-adjacent log lines.
    """
    target = state.get("target", "")
    log: list[str] = ["[recon] Crawling + probing target to map attack surface..."]

    # Two recon passes: follow links (crawl), then probe common paths
    # (discover). Dedupe by (url, method) so a path found both ways counts once.
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for ep in crawl(target):
        d = ep.model_dump()
        by_key[(d["url"], d["method"])] = d
    crawled = len(by_key)

    for ep in discover_paths(target):
        d = ep.model_dump()
        by_key.setdefault((d["url"], d["method"]), d)
    probed = len(by_key) - crawled

    surface = list(by_key.values())
    forms = sum(1 for ep in surface if ep.get("has_form"))
    log.append(
        f"[recon] Mapped {len(surface)} endpoint(s) "
        f"({crawled} crawled, {probed} via path probing; {forms} with forms)."
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
