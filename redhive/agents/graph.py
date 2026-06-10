"""LangGraph wiring for the RedHive multi-agent team.

Builds a ``StateGraph`` over the shared ``EngagementState`` contract and
exposes two public entrypoints the API depends on:

    build_graph()                          -> compiled graph
    run_engagement(target, log_callback)   -> final state dict

Edge structure::

    START -> orchestrator -> (scope refused) -> END
                          \\-> recon -> lead -> plan_probes
                                 ==(Send × N)==> probe (parallel swarm)
                                 -> aggregate -> validator -> lead_review
                                 -> (deepen) plan_probes  | (finish) reporter
                                 -> patch -> strategist -> END

The testing phase is a map-reduce *swarm*: ``plan_probes`` expands the attack
surface into N tasks, ``fan_out_probes`` emits a ``Send`` per task so the probe
agents run concurrently in one super-step, and ``aggregate`` fans them back in.

Reducer channels (``operator.add``): ``log`` accumulates progress lines across
the whole run, and ``raw_findings`` merges the concurrent writes from the probe
swarm. Everything else is last-write-wins, owned by a single node per round.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Callable, TypedDict

from langgraph.graph import END, START, StateGraph

from redhive.agents.lead import lead
from redhive.agents.lead_review import lead_review
from redhive.agents.orchestrator import orchestrator
from redhive.agents.patch import patch
from redhive.agents.probe import aggregate, fan_out_probes, plan_probes, probe
from redhive.agents.recon import recon
from redhive.agents.reporter import reporter
from redhive.agents.strategist import strategist
from redhive.agents.validator import validator
from redhive.models import EngagementState


class _GraphState(TypedDict, total=False):
    """The graph's channel schema — declared explicitly (not by subclassing
    ``EngagementState``), because LangGraph derives channels from this exact
    TypedDict and subclass-inherited fields were not registering as channels.

    Mirrors the public ``EngagementState`` contract plus the loop's working
    fields. Only ``log`` gets an ``operator.add`` reducer so progress lines
    accumulate across the run; every other field is last-write-wins, owned by a
    single node per round (``attack_surface``/``fingerprint`` by recon, ``plan``
    by lead, ``findings``/``confirmed`` rewritten wholesale by tester/validator,
    the loop counters by ``lead_review``).
    """

    target: str
    scope_allowed: bool
    attack_surface: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    confirmed: list[dict[str, Any]]
    patches: list[dict[str, Any]]
    plan: list[str]
    log: Annotated[list[str], operator.add]
    done: bool
    # Working fields for recon hand-off and the iterative loop.
    fingerprint: dict[str, Any]
    round: int
    max_rounds: int
    next_action: str
    deep_pass: bool
    # Parallel probe swarm. ``raw_findings`` MUST have a reducer: the fanned-out
    # probe agents all write it concurrently in one super-step, and the reducer
    # merges those writes instead of raising a concurrent-update error.
    probe_tasks: list[dict[str, Any]]
    raw_findings: Annotated[list[dict[str, Any]], operator.add]
    agents_dispatched: int
    # Post-engagement intelligence (patch / strategist nodes).
    attack_chains: list[dict[str, Any]]
    risk_score: int


def _route_after_orchestrator(state: EngagementState) -> str:
    """Conditional edge: skip the scan entirely if the target is out of scope."""
    return "recon" if state.get("scope_allowed") else END


def _route_after_review(state: dict[str, Any]) -> str:
    """Conditional edge: loop back for a deeper pass, or finish up."""
    return "plan_probes" if state.get("next_action") == "deepen" else "reporter"


def build_graph():
    """Build and compile the multi-agent engagement graph."""
    builder = StateGraph(_GraphState)

    builder.add_node("orchestrator", orchestrator)
    builder.add_node("recon", recon)
    builder.add_node("lead", lead)
    builder.add_node("plan_probes", plan_probes)
    builder.add_node("probe", probe)
    builder.add_node("aggregate", aggregate)
    builder.add_node("validator", validator)
    builder.add_node("lead_review", lead_review)
    builder.add_node("reporter", reporter)
    builder.add_node("patch", patch)
    builder.add_node("strategist", strategist)

    builder.add_edge(START, "orchestrator")
    builder.add_conditional_edges(
        "orchestrator",
        _route_after_orchestrator,
        {"recon": "recon", END: END},
    )
    builder.add_edge("recon", "lead")
    builder.add_edge("lead", "plan_probes")
    # Map: fan a Send out to a probe agent per task — they run concurrently.
    builder.add_conditional_edges("plan_probes", fan_out_probes, ["probe"])
    # Reduce: every probe flows into aggregate, which fans the results in.
    builder.add_edge("probe", "aggregate")
    builder.add_edge("aggregate", "validator")
    # After validation the Lead reviews results and may loop for a deeper pass.
    builder.add_edge("validator", "lead_review")
    builder.add_conditional_edges(
        "lead_review",
        _route_after_review,
        {"plan_probes": "plan_probes", "reporter": "reporter"},
    )
    # Finish path: report -> auto-remediation -> exploit-chain/risk -> END.
    builder.add_edge("reporter", "patch")
    builder.add_edge("patch", "strategist")
    builder.add_edge("strategist", END)

    return builder.compile()


def run_engagement(
    target: str, log_callback: Callable[[str], None] | None = None
) -> dict:
    """Run the full multi-agent scan synchronously. Returns the final
    EngagementState as a dict. If log_callback is given, call it with each
    new log line as it is produced (for live streaming)."""
    graph = build_graph()
    initial: dict[str, Any] = {
        "target": target,
        "log": [],
        "done": False,
        "round": 0,
        "max_rounds": 2,
        "deep_pass": False,
    }
    # LangGraph caps super-steps; raise it so a multi-round loop can complete.
    graph = graph.with_config(recursion_limit=50)

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
