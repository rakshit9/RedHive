"""HillClimb memory — cross-scan regression tracking.

RedHive remembers what it found on a target before. When the same target is
re-scanned, each finding is tagged ``new`` or ``recurring``, and issues that
were present last time but are now gone are reported as ``fixed``. This mirrors
MindFort's continuous / self-improving angle: the platform gets more useful the
more often it runs.

Matching is by (category, title) — stable across re-scans of the same site even
when the exact URL varies.
"""

from __future__ import annotations

from typing import Any


def _key(finding: dict[str, Any]) -> tuple[str, str]:
    return (
        str(finding.get("category", "")).strip().lower(),
        str(finding.get("title", "")).strip().lower(),
    )


def diff_findings(
    previous: list[dict[str, Any]], current: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    """Compare a target's previous findings against the current ones.

    Returns ``(annotated_current, fixed, summary)`` where each current finding
    gains a ``regression`` key ("new" | "recurring"), ``fixed`` lists issues
    that disappeared since last scan, and ``summary`` counts each bucket.
    """
    prev_keys = {_key(f) for f in previous}
    curr_keys = {_key(f) for f in current}

    annotated: list[dict[str, Any]] = []
    for f in current:
        g = dict(f)
        g["regression"] = "recurring" if _key(f) in prev_keys else "new"
        annotated.append(g)

    fixed = [dict(f, regression="fixed") for f in previous if _key(f) not in curr_keys]

    summary = {
        "new": sum(1 for f in annotated if f["regression"] == "new"),
        "recurring": sum(1 for f in annotated if f["regression"] == "recurring"),
        "fixed": len(fixed),
    }
    return annotated, fixed, summary
