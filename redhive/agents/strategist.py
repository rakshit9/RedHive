"""Strategist node — autonomous exploit chaining + risk scoring.

The final intelligence pass. Instead of leaving findings as a flat list, the
strategist reasons (via the LLM) about how an attacker would *chain* them into
a real attack path — e.g. "exposed .env leaks DB creds -> confirmed SQLi ->
admin takeover". It also computes a single 0-100 risk score so a stakeholder
gets one number. This is the difference between a scanner and an analyst.
"""

from __future__ import annotations

import json
from typing import Any

from redhive.llm import get_llm
from redhive.models import EngagementState, normalize_severity

# Per-finding risk weights; the score saturates toward 100 as severe issues stack.
_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 1}

_SYSTEM = (
    "You are a lead penetration tester writing the 'attack narrative' section "
    "of a report for an authorized engagement. Given the confirmed findings, "
    "identify realistic ATTACK CHAINS: ordered steps where one weakness enables "
    "the next, ending in concrete impact. Reply with ONLY a JSON array; each "
    "item is an object {\"name\": str, \"steps\": [str, ...], \"impact\": str}. "
    "1-3 chains. No prose, no markdown."
)


def _risk_score(confirmed: list[dict[str, Any]]) -> int:
    """Aggregate severities into a saturating 0-100 risk score."""
    raw = sum(_WEIGHT.get(normalize_severity(f.get("severity")), 1) for f in confirmed)
    # Saturate so a handful of highs already reads as high risk.
    return min(100, raw)


def _parse_chains(text: str) -> list[dict[str, Any]]:
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        raw = raw[raw.find("[") :] if "[" in raw else raw
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        start, end = raw.find("["), raw.rfind("]")
        if start == -1 or end <= start:
            return []
        try:
            data = json.loads(raw[start : end + 1])
        except (json.JSONDecodeError, ValueError):
            return []
    if not isinstance(data, list):
        return []
    chains: list[dict[str, Any]] = []
    for item in data:
        if isinstance(item, dict) and item.get("steps"):
            chains.append(
                {
                    "name": str(item.get("name", "Attack chain")),
                    "steps": [str(s) for s in item.get("steps", [])],
                    "impact": str(item.get("impact", "")),
                }
            )
    return chains


def strategist(state: EngagementState) -> dict[str, Any]:
    """Chain confirmed findings into attack paths and compute a risk score."""
    confirmed: list[dict[str, Any]] = state.get("confirmed", [])
    score = _risk_score(confirmed)
    band = (
        "CRITICAL" if score >= 80 else
        "HIGH" if score >= 50 else
        "MEDIUM" if score >= 20 else
        "LOW"
    )
    log: list[str] = [
        f"[strategist] Risk score {score}/100 ({band}). Reasoning about attack chains..."
    ]

    chains: list[dict[str, Any]] = []
    if confirmed:
        brief = [
            {"title": f.get("title"), "category": f.get("category"),
             "severity": normalize_severity(f.get("severity")), "target": f.get("target")}
            for f in confirmed
        ]
        try:
            llm = get_llm(temperature=0.2)
            resp = llm.invoke(
                [("system", _SYSTEM), ("human", json.dumps({"findings": brief}))]
            )
            chains = _parse_chains(str(getattr(resp, "content", "")))
            log.append(f"[strategist] Identified {len(chains)} attack chain(s).")
        except Exception as exc:  # noqa: BLE001 — never let the LLM crash the finish
            log.append(f"[strategist] LLM chaining unavailable ({exc!r}).")

    return {"attack_chains": chains, "risk_score": score, "log": log, "done": True}
