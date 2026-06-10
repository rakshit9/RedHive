"""Shared data contract for the whole system.

EVERY agent, tool, and the API build against these shapes. Do not change
field names without updating all consumers.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, TypedDict

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_VALID_SEVERITIES = {s.value for s in Severity}


def normalize_severity(value: object) -> str:
    """Coerce any severity-ish value to a valid lowercase ``Severity`` string.

    Handles plain strings, ``Severity`` enum members, and stringified enums
    like ``"Severity.HIGH"`` (what ``str()`` yields for a ``(str, Enum)``).
    Serialized findings carry the enum member until the Reporter runs, so every
    consumer that reasons over severity must normalize through here.
    """
    if isinstance(value, Severity):
        return value.value
    sev = str(value or "").strip().lower()
    if "." in sev:  # e.g. "severity.high" -> "high"
        sev = sev.rsplit(".", 1)[-1]
    return sev if sev in _VALID_SEVERITIES else Severity.INFO.value


class Endpoint(BaseModel):
    """A discovered piece of attack surface (from the Recon agent)."""

    url: str
    method: str = "GET"
    params: list[str] = Field(default_factory=list)
    has_form: bool = False
    notes: str = ""


class Finding(BaseModel):
    """A single vulnerability. Mirrors MindFort's 'proof + repro + fix'."""

    title: str
    category: str  # e.g. "XSS", "SQLi", "Security Headers", "Exposed File"
    severity: Severity = Severity.INFO
    target: str  # the URL/endpoint the finding applies to

    # Evidence / proof-of-exploit
    description: str = ""
    evidence: str = ""  # raw request/response snippet proving it
    reproduction: list[str] = Field(default_factory=list)  # step-by-step

    # Remediation (LLM-written)
    remediation: str = ""

    # Validation lifecycle
    confirmed: bool = False
    false_positive: bool = False
    discovered_by: str = ""  # which agent produced it


class Patch(BaseModel):
    """A suggested fix for a finding (stretch goal: auto-PR)."""

    finding_title: str
    file_hint: str = ""
    diff: str = ""
    explanation: str = ""


class EngagementState(TypedDict, total=False):
    """Shared scratchpad passed between agents in the LangGraph.

    Each agent reads what it needs and writes its results back here.
    """

    target: str
    scope_allowed: bool
    attack_surface: list[dict[str, Any]]  # serialized Endpoint list
    findings: list[dict[str, Any]]  # aggregated, serialized Finding list
    confirmed: list[dict[str, Any]]  # after Validator
    patches: list[dict[str, Any]]
    plan: list[str]  # Lead agent's current to-do
    log: list[str]  # human-readable live log for the UI
    done: bool

    # Parallel probe-agent swarm (see redhive.agents.probe). ``probe_tasks`` is
    # the dispatched task list; ``raw_findings`` is the reducer channel the
    # concurrent probe agents append to; ``agents_dispatched`` is the swarm size
    # (surfaced in the log/UI as proof of parallel fan-out).
    probe_tasks: list[dict[str, Any]]
    raw_findings: list[dict[str, Any]]
    agents_dispatched: int

    # Recon hand-off + iterative-loop bookkeeping. These must live on the
    # public contract (not just the graph's internal schema) because LangGraph
    # derives each node's input keys from its ``state: EngagementState``
    # annotation — fields absent here are silently withheld from those nodes.
    fingerprint: dict[str, Any]  # recon -> lead/tester
    round: int  # iterative-loop round counter (lead_review)
    max_rounds: int  # loop cap
    next_action: str  # "deepen" | "finish" (lead_review -> routing)
    deep_pass: bool  # widen tester coverage on a later round

    # Post-engagement intelligence.
    attack_chains: list[dict[str, Any]]  # strategist: chained attack paths
    risk_score: int  # strategist: overall 0-100 risk score
