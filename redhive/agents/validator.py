"""Validator (Senior reviewer) node.

A sanity/de-dupe pass over the raw findings to mirror MindFort's "<1%
false-positive" claim. Exact duplicates (same title + target) are marked as
false positives; everything that survives is marked ``confirmed=True`` and
moved into ``state["confirmed"]``. This is deterministic on purpose — the
expensive reasoning lives in the Lead and Reporter nodes.
"""

from __future__ import annotations

from typing import Any

from redhive.models import EngagementState


def validator(state: EngagementState) -> dict[str, Any]:
    """Re-check raw findings; confirm the real ones, drop the dupes."""
    raw: list[dict[str, Any]] = state.get("findings", [])
    log: list[str] = [f"[validator] Reviewing {len(raw)} raw finding(s)..."]

    confirmed: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    dupes = 0
    empties = 0

    # Work on copies so we don't mutate the raw findings list in place.
    reviewed: list[dict[str, Any]] = []
    for f in raw:
        finding = dict(f)
        title = str(finding.get("title", "")).strip()
        target = str(finding.get("target", "")).strip()

        # Obvious non-finding: no title at all.
        if not title:
            finding["false_positive"] = True
            empties += 1
            reviewed.append(finding)
            continue

        key = (title.lower(), target.lower())
        if key in seen:
            finding["false_positive"] = True
            finding["confirmed"] = False
            dupes += 1
            reviewed.append(finding)
            continue

        seen.add(key)
        finding["confirmed"] = True
        finding["false_positive"] = False
        finding["discovered_by"] = finding.get("discovered_by") or "tools"
        reviewed.append(finding)
        confirmed.append(finding)

    log.append(
        f"[validator] Confirmed {len(confirmed)} finding(s); "
        f"dropped {dupes} duplicate(s) and {empties} empty result(s)."
    )

    return {"findings": reviewed, "confirmed": confirmed, "log": log}
