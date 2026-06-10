"""Per-scan LLM token + cost tracking.

A scan calls the LLM in a handful of orchestration nodes (lead, lead_review,
reporter, patch, strategist) — the parallel probe swarm uses none. We attach a
callback to the LangGraph run that aggregates ``usage_metadata`` across every
LLM call (provider-agnostic: works for both OpenAI and Anthropic), then turn
the totals into an estimated USD cost from a small pricing table.

This is both a cost-visibility feature for customers and a cheap way to prove
the architecture's efficiency (token cost scales with findings, not with how
many agents/endpoints were scanned).
"""

from __future__ import annotations

from typing import Any

from langchain_core.callbacks import UsageMetadataCallbackHandler

# USD per 1M tokens, (input, output). Matched by substring against the model id,
# so dated/suffixed names (e.g. "gpt-4o-2024-..") still resolve.
_PRICING: list[tuple[str, float, float]] = [
    ("gpt-4o-mini", 0.15, 0.60),
    ("gpt-4o", 2.50, 10.00),
    ("gpt-4.1-mini", 0.40, 1.60),
    ("gpt-4.1", 2.00, 8.00),
    ("o4-mini", 1.10, 4.40),
    ("claude-3-5-haiku", 0.80, 4.00),
    ("claude-haiku", 1.00, 5.00),
    ("claude-3-5-sonnet", 3.00, 15.00),
    ("claude-sonnet", 3.00, 15.00),
    ("claude-opus", 15.00, 75.00),
]
_DEFAULT_RATES = (2.50, 10.00)  # fall back to gpt-4o-class pricing


def _rates_for(model: str) -> tuple[float, float]:
    m = (model or "").lower()
    for needle, in_rate, out_rate in _PRICING:
        if needle in m:
            return in_rate, out_rate
    return _DEFAULT_RATES


class ScanUsage:
    """Wraps a usage callback and turns the aggregate into a cost summary."""

    def __init__(self) -> None:
        self._tracker = _CountingUsageHandler()

    @property
    def handler(self):
        return self._tracker

    def summary(self) -> dict[str, Any]:
        meta: dict[str, dict[str, int]] = dict(self._tracker.usage_metadata or {})
        input_tokens = output_tokens = total_tokens = 0
        cost = 0.0
        for model, u in meta.items():
            it = int(u.get("input_tokens", 0) or 0)
            ot = int(u.get("output_tokens", 0) or 0)
            tt = int(u.get("total_tokens", 0) or (it + ot))
            input_tokens += it
            output_tokens += ot
            total_tokens += tt
            in_rate, out_rate = _rates_for(model)
            cost += it / 1_000_000 * in_rate + ot / 1_000_000 * out_rate
        return {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens or (input_tokens + output_tokens),
            "llm_calls": self._tracker.calls,
            "cost_usd": round(cost, 4),
            "by_model": meta,
        }


class _CountingUsageHandler(UsageMetadataCallbackHandler):
    """UsageMetadataCallbackHandler that also counts how many LLM calls ran."""

    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:  # noqa: ANN401
        self.calls += 1
        super().on_llm_end(response, **kwargs)
