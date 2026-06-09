"""The RedHive multi-agent team (LangGraph).

A StateGraph over ``EngagementState`` where each node is one role on the
pentest team: orchestrator -> recon -> lead -> tester -> validator ->
reporter. The public entrypoints live in ``redhive.agents.graph``.
"""

from __future__ import annotations

from redhive.agents.graph import build_graph, run_engagement

__all__ = ["build_graph", "run_engagement"]
