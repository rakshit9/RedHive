"""Tests for per-scan LLM token + cost tracking."""

from __future__ import annotations

from redhive import usage


def test_rates_match_by_substring():
    assert usage._rates_for("gpt-4o-2024-08-06") == (2.50, 10.00)
    assert usage._rates_for("gpt-4o-mini") == (0.15, 0.60)
    assert usage._rates_for("claude-sonnet-4-6") == (3.00, 15.00)
    # Unknown model falls back to gpt-4o-class pricing.
    assert usage._rates_for("some-future-model") == usage._DEFAULT_RATES


def test_summary_aggregates_and_costs():
    u = usage.ScanUsage()
    # Simulate what the callback would have accumulated.
    u.handler.usage_metadata = {
        "gpt-4o-2024-08-06": {"input_tokens": 1000, "output_tokens": 500, "total_tokens": 1500}
    }
    u.handler.calls = 3

    s = u.summary()
    assert s["input_tokens"] == 1000
    assert s["output_tokens"] == 500
    assert s["total_tokens"] == 1500
    assert s["llm_calls"] == 3
    # 1000/1e6*2.5 + 500/1e6*10 = 0.0025 + 0.005 = 0.0075
    assert s["cost_usd"] == 0.0075


def test_summary_handles_multiple_models():
    u = usage.ScanUsage()
    u.handler.usage_metadata = {
        "gpt-4o": {"input_tokens": 1000, "output_tokens": 0, "total_tokens": 1000},
        "gpt-4o-mini": {"input_tokens": 1000, "output_tokens": 0, "total_tokens": 1000},
    }
    s = u.summary()
    assert s["total_tokens"] == 2000
    # 1000/1e6*2.5 + 1000/1e6*0.15 = 0.0025 + 0.00015 = 0.00265
    assert s["cost_usd"] == 0.0027  # rounded to 4dp
