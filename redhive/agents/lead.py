"""Team Lead node — the agentic decision step.

Reasons (via the LLM) over the recon output and fingerprint to decide which
tests actually matter for this target, then writes a short, ordered plan into
``state["plan"]``. This is the differentiator: the team doesn't blindly run
every probe, it *chooses*. If the LLM is unavailable the node degrades to a
sensible deterministic plan so the engagement still completes.
"""

from __future__ import annotations

import json
from typing import Any

from redhive.llm import get_llm
from redhive.models import EngagementState

_SYSTEM = (
    "You are the Lead pentester on an authorized security engagement against "
    "a practice target. You are given the discovered attack surface and a tech "
    "fingerprint. Decide which of these tests matter and in what order: "
    "security_headers, tls, exposed_files. Reply with ONLY a JSON array of "
    "short imperative strings, e.g. "
    '["Check security headers on the login form", "Probe for exposed files"]. '
    "No prose, no markdown — just the JSON array."
)

# Tests this team can actually run; the Lead picks from these.
_KNOWN_TESTS = ("security_headers", "tls", "exposed_files")


def _fallback_plan(surface: list[dict[str, Any]], fp: dict[str, Any]) -> list[str]:
    """Deterministic plan used when the LLM call is unavailable/invalid."""
    plan = [
        "Check security headers across discovered endpoints.",
        "Probe for exposed sensitive files (.git, .env, backups).",
    ]
    if any(ep.get("has_form") for ep in surface):
        plan.insert(0, "Prioritize the login/form endpoints — test headers + cookie flags.")
    target_is_https = any(str(ep.get("url", "")).startswith("https") for ep in surface)
    if target_is_https or (fp.get("server") and "https" in str(fp.get("server")).lower()):
        plan.append("Inspect the TLS posture (protocol version + cert expiry).")
    return plan


def lead(state: EngagementState) -> dict[str, Any]:
    """Reason over recon output and write the test plan into ``plan``."""
    surface: list[dict[str, Any]] = state.get("attack_surface", [])
    fp: dict[str, Any] = state.get("fingerprint", {})  # type: ignore[typeddict-item]
    log: list[str] = ["[lead] Reasoning over attack surface to select tests..."]

    # Keep the prompt tight: a trimmed surface + the fingerprint summary.
    surface_brief = [
        {"url": ep.get("url"), "method": ep.get("method"), "has_form": ep.get("has_form")}
        for ep in surface[:15]
    ]
    user = json.dumps(
        {
            "target": state.get("target", ""),
            "fingerprint": {
                "server": fp.get("server"),
                "technologies": fp.get("technologies", []),
            },
            "endpoints": surface_brief,
            "available_tests": list(_KNOWN_TESTS),
        }
    )

    plan: list[str] = []
    try:
        llm = get_llm(temperature=0.0)
        resp = llm.invoke([("system", _SYSTEM), ("human", user)])
        text = getattr(resp, "content", str(resp))
        plan = _parse_plan(text)
        if plan:
            log.append(f"[lead] LLM selected {len(plan)} test(s).")
    except Exception as exc:  # noqa: BLE001 — never let the LLM crash the scan
        log.append(f"[lead] LLM reasoning unavailable ({exc!r}); using fallback plan.")

    if not plan:
        plan = _fallback_plan(surface, fp)
        log.append(f"[lead] Fallback plan with {len(plan)} step(s).")

    for step in plan:
        log.append(f"[lead]   - {step}")

    return {"plan": plan, "log": log}


def _parse_plan(text: str) -> list[str]:
    """Best-effort parse of a JSON array of plan strings from LLM output."""
    if not text:
        return []
    raw = text.strip()
    # Strip ```json fences if the model added them despite instructions.
    if raw.startswith("```"):
        raw = raw.strip("`")
        raw = raw[raw.find("[") :] if "[" in raw else raw
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        # Salvage a bracketed array if there's surrounding prose.
        start, end = raw.find("["), raw.rfind("]")
        if start != -1 and end != -1 and end > start:
            try:
                data = json.loads(raw[start : end + 1])
            except (json.JSONDecodeError, ValueError):
                return []
        else:
            return []
    if isinstance(data, list):
        return [str(item).strip() for item in data if str(item).strip()]
    return []
