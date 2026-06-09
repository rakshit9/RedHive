"""LangGraph wiring for the RedHive multi-agent team.

Builds a ``StateGraph`` over the shared ``EngagementState`` contract and
exposes two public entrypoints the API depends on:

    build_graph()                          -> compiled graph
    run_engagement(target, log_callback)   -> final state dict

Edge structure::

    START -> orchestrator -> (scope refused) -> END
                          \\-> recon -> lead -> tester
                                 -> validator -> reporter -> END

The accumulating list fields (``log``, ``attack_surface``, ``findings``,
``confirmed``, ``plan``) use ``operator.add`` reducers so each node can return
a partial update and have it merged rather than overwrite prior state.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Callable

from langgraph.graph import END, START, StateGraph

from redhive.agents.lead import lead
from redhive.agents.orchestrator import orchestrator
from redhive.agents.recon import recon
from redhive.agents.reporter import reporter
from redhive.agents.tester import tester
from redhive.agents.validator import validator
from redhive.models import EngagementState


class _GraphState(EngagementState, total=False):
    """Internal state with a reducer for the live log.

    Same shape as ``EngagementState`` (the public contract). Only ``log`` gets
    an ``operator.add`` reducer, because every node *appends* progress lines and
    we want them to accumulate across the whole run. All other fields keep the
    default last-write-wins: each is produced (and, where re-processed, fully
    rewritten) by a single owning node — ``attack_surface`` by recon, ``plan``
    by lead, ``findings``/``confirmed`` by tester then rewritten wholesale by
    validator/reporter — so appending them would create duplicates. The Recon
    agent also stashes a ``fingerprint`` dict here for the Lead to reason over.
    """

    log: Annotated[list[str], operator.add]
    fingerprint: dict[str, Any]


def _route_after_orchestrator(state: EngagementState) -> str:
    """Conditional edge: skip the scan entirely if the target is out of scope."""
    return "recon" if state.get("scope_allowed") else END


def build_graph():
    """Build and compile the multi-agent engagement graph."""
    builder = StateGraph(_GraphState)

    builder.add_node("orchestrator", orchestrator)
    builder.add_node("recon", recon)
    builder.add_node("lead", lead)
    builder.add_node("tester", tester)
    builder.add_node("validator", validator)
    builder.add_node("reporter", reporter)

    builder.add_edge(START, "orchestrator")
    builder.add_conditional_edges(
        "orchestrator",
        _route_after_orchestrator,
        {"recon": "recon", END: END},
    )
    builder.add_edge("recon", "lead")
    builder.add_edge("lead", "tester")
    builder.add_edge("tester", "validator")
    builder.add_edge("validator", "reporter")
    builder.add_edge("reporter", END)

    return builder.compile()


def run_engagement(
    target: str, log_callback: Callable[[str], None] | None = None
) -> dict:
    """Run the full multi-agent scan synchronously. Returns the final
    EngagementState as a dict. If log_callback is given, call it with each
    new log line as it is produced (for live streaming)."""
    graph = build_graph()
    initial: dict[str, Any] = {"target": target, "log": [], "done": False}

    if log_callback is None:
        # Simple path: run to completion and return the final state.
        return dict(graph.invoke(initial))

    # Streaming path: emit each new log line as nodes complete. We stream node
    # updates and diff the cumulative log so the callback sees lines in order.
    final_state: dict[str, Any] = dict(initial)
    emitted = 0
    accumulated: list[str] = []

    for chunk in graph.stream(initial, stream_mode="values"):
        final_state = dict(chunk)
        accumulated = final_state.get("log", []) or []
        while emitted < len(accumulated):
            try:
                log_callback(accumulated[emitted])
            except Exception:  # noqa: BLE001 — a bad callback must not kill the scan
                pass
            emitted += 1

    return final_state
