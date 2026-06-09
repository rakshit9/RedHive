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
    findings: list[dict[str, Any]]  # raw, serialized Finding list
    confirmed: list[dict[str, Any]]  # after Validator
    patches: list[dict[str, Any]]
    plan: list[str]  # Lead agent's current to-do
    log: list[str]  # human-readable live log for the UI
    done: bool
