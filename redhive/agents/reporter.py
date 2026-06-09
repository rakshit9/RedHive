"""Report writer node.

Writes a concise, actionable ``remediation`` for each confirmed finding (via
the LLM), normalizes severities to the ``Severity`` enum, and appends a final
human-readable summary to the log. Sets ``done=True``. If the LLM is
unavailable each finding falls back to its tool-supplied description so the
report is still useful.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from redhive.llm import get_llm
from redhive.models import EngagementState, Severity, normalize_severity

_SYSTEM = (
    "You are a senior application-security engineer writing the remediation "
    "section of a pentest report. Given one finding, write a single concise "
    "paragraph (2-3 sentences) telling the developer exactly how to fix it. "
    "Be specific and actionable. Output only the remediation text — no "
    "preamble, no markdown headers."
)

# Severity ordering for the summary roll-up (high -> low).
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _llm_remediation(llm: Any, finding: dict[str, Any]) -> str:
    """Ask the LLM for a remediation paragraph for one finding."""
    user = (
        f"Title: {finding.get('title')}\n"
        f"Category: {finding.get('category')}\n"
        f"Severity: {finding.get('severity')}\n"
        f"Target: {finding.get('target')}\n"
        f"Description: {finding.get('description')}\n"
        f"Evidence: {finding.get('evidence')}"
    )
    resp = llm.invoke([("system", _SYSTEM), ("human", user)])
    text = getattr(resp, "content", str(resp))
    return str(text).strip()


def reporter(state: EngagementState) -> dict[str, Any]:
    """Write remediation per confirmed finding and a final summary."""
    confirmed: list[dict[str, Any]] = state.get("confirmed", [])
    log: list[str] = [
        f"[reporter] Writing remediation for {len(confirmed)} confirmed finding(s)..."
    ]

    # Spin up the LLM once; if it fails, every finding uses its fallback.
    llm: Any = None
    try:
        llm = get_llm(temperature=0.0)
    except Exception as exc:  # noqa: BLE001
        log.append(f"[reporter] LLM unavailable ({exc!r}); using description-based remediation.")

    reported: list[dict[str, Any]] = []
    for f in confirmed:
        finding = dict(f)
        finding["severity"] = normalize_severity(finding.get("severity"))

        remediation = ""
        if llm is not None and not finding.get("remediation"):
            try:
                remediation = _llm_remediation(llm, finding)
            except Exception as exc:  # noqa: BLE001 — degrade per finding
                log.append(
                    f"[reporter] LLM remediation failed for "
                    f"{finding.get('title')!r} ({exc!r}); using fallback."
                )
        if not remediation:
            remediation = finding.get("remediation") or (
                f"Address the issue described: {finding.get('description', '')}".strip()
            )
        finding["remediation"] = remediation
        reported.append(finding)

    # --- Final summary ---------------------------------------------------
    counts = Counter(f["severity"] for f in reported)
    roll_up = ", ".join(
        f"{counts[s]} {s}" for s in _SEVERITY_ORDER if counts.get(s)
    ) or "no confirmed findings"
    log.append(
        f"[reporter] Engagement complete for {state.get('target', '')!r} — "
        f"{len(reported)} confirmed finding(s): {roll_up}."
    )

    return {"confirmed": reported, "log": log, "done": True}
