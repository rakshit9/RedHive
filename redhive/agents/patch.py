"""Patch agent — auto-remediation.

For the highest-impact confirmed findings, the agent drafts a concrete fix:
a code/config diff plus a one-line explanation. This mirrors MindFort's
"generates verified patches / opens a PR" differentiator — RedHive doesn't just
report problems, it proposes the change that closes them.

If a target repo is configured (see ``redhive.github_pr``) the API layer can
take these patches and open a pull request; here we only produce them.
"""

from __future__ import annotations

from typing import Any

from redhive.llm import get_llm
from redhive.models import EngagementState, Patch, normalize_severity

# Only patch issues worth a code change, and cap the count to bound LLM cost.
_PATCHABLE = {"Security Headers", "CORS", "CSRF", "XSS", "SQLi", "Open Redirect"}
_MAX_PATCHES = 6
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_SYSTEM = (
    "You are a security engineer writing a minimal fix for one vulnerability. "
    "Given the finding, output a concrete remediation as: a one-line file/location "
    "hint, then a fenced code block with the exact config or code change to apply. "
    "Keep it short and copy-pasteable. Assume a typical web stack (nginx/express/"
    "flask). Do not explain at length."
)


def _draft_patch(llm: Any, finding: dict[str, Any]) -> Patch:
    """Ask the LLM for a concrete fix for one finding."""
    user = (
        f"Title: {finding.get('title')}\n"
        f"Category: {finding.get('category')}\n"
        f"Target: {finding.get('target')}\n"
        f"Evidence: {finding.get('evidence')}"
    )
    resp = llm.invoke([("system", _SYSTEM), ("human", user)])
    text = str(getattr(resp, "content", "")).strip()

    # Split a leading "file hint" line from the fenced diff/code if present.
    file_hint, diff = "", text
    if "```" in text:
        head, _, rest = text.partition("```")
        file_hint = head.strip().splitlines()[-1].strip() if head.strip() else ""
        diff = "```" + rest
    return Patch(
        finding_title=str(finding.get("title", "")),
        file_hint=file_hint,
        diff=diff,
        explanation=f"Fix for {finding.get('category')} on {finding.get('target')}.",
    )


def patch(state: EngagementState) -> dict[str, Any]:
    """Draft remediation patches for the top confirmed findings."""
    confirmed: list[dict[str, Any]] = state.get("confirmed", [])
    candidates = [f for f in confirmed if f.get("category") in _PATCHABLE]
    candidates.sort(key=lambda f: _SEV_RANK.get(normalize_severity(f.get("severity")), 9))
    candidates = candidates[:_MAX_PATCHES]

    log: list[str] = [
        f"[patch] Drafting fixes for {len(candidates)} high-impact finding(s)..."
    ]

    patches: list[dict[str, Any]] = []
    llm: Any = None
    try:
        llm = get_llm(temperature=0.0)
    except Exception as exc:  # noqa: BLE001
        log.append(f"[patch] LLM unavailable ({exc!r}); skipping patch generation.")

    if llm is not None:
        for f in candidates:
            try:
                patches.append(_draft_patch(llm, f).model_dump())
            except Exception as exc:  # noqa: BLE001 — degrade per finding
                log.append(f"[patch] Could not draft fix for {f.get('title')!r} ({exc!r}).")

    log.append(f"[patch] Produced {len(patches)} patch(es).")
    return {"patches": patches, "log": log}
