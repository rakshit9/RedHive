"""Lead review node — the iterative decision step.

After the Validator confirms a round of findings, the Lead steps back and
decides like a real attacker would: *is it worth digging deeper, or are we
done?* If deeper testing is warranted (and we are under the round cap) it
flags a deep pass and loops the team back to the Tester; otherwise it hands
off to the Reporter.

The decision uses the LLM when available, with a deterministic fallback so
the engagement always terminates.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from redhive.llm import get_llm
from redhive.models import normalize_severity

_SYSTEM = (
    "You are the Lead pentester deciding whether to run another, deeper round "
    "of testing on an authorized practice target. You are given the current "
    "round number, the cap, and a severity breakdown of confirmed findings. "
    "If high/medium issues suggest more attack surface is worth probing and we "
    "are under the cap, reply DEEPEN. If coverage looks sufficient, reply "
    "FINISH. Reply with ONLY the single word DEEPEN or FINISH."
)


def _heuristic(counts: Counter, round_no: int, max_rounds: int) -> bool:
    """Deepen when there is real signal and we still have rounds left."""
    if round_no >= max_rounds:
        return False
    high_value = counts.get("critical", 0) + counts.get("high", 0) + counts.get("medium", 0)
    return high_value > 0


def lead_review(state: dict[str, Any]) -> dict[str, Any]:
    """Decide whether to loop for a deeper pass or finish."""
    round_no = int(state.get("round", 0)) + 1
    max_rounds = int(state.get("max_rounds", 2))
    confirmed: list[dict[str, Any]] = state.get("confirmed", [])
    counts = Counter(normalize_severity(f.get("severity")) for f in confirmed)

    log: list[str] = [
        f"[lead] Reviewing round {round_no}/{max_rounds} results "
        f"({len(confirmed)} confirmed)..."
    ]

    # Past the cap there is nothing to decide — always finish.
    if round_no >= max_rounds:
        log.append("[lead] Round cap reached — finalizing the report.")
        return {"round": round_no, "next_action": "finish", "deep_pass": False, "log": log}

    deepen = _heuristic(counts, round_no, max_rounds)
    try:
        llm = get_llm(temperature=0.0)
        user = (
            f"Round {round_no} of {max_rounds}. "
            f"Confirmed by severity: {dict(counts)}."
        )
        resp = llm.invoke([("system", _SYSTEM), ("human", user)])
        text = str(getattr(resp, "content", "")).strip().upper()
        if "DEEPEN" in text:
            deepen = True
        elif "FINISH" in text:
            deepen = False
        log.append(f"[lead] Decision: {'DEEPEN' if deepen else 'FINISH'} (LLM).")
    except Exception as exc:  # noqa: BLE001 — never let the LLM stall the loop
        log.append(
            f"[lead] LLM review unavailable ({exc!r}); "
            f"heuristic says {'DEEPEN' if deepen else 'FINISH'}."
        )

    if deepen:
        log.append("[lead] Escalating: widening coverage for a deeper pass.")
        return {"round": round_no, "next_action": "deepen", "deep_pass": True, "log": log}

    return {"round": round_no, "next_action": "finish", "deep_pass": False, "log": log}
