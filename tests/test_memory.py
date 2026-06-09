"""Tests for HillClimb cross-scan diffing."""

from __future__ import annotations

from redhive.memory import diff_findings


def _f(title, category="Security Headers"):
    return {"title": title, "category": category}


def test_diff_classifies_new_recurring_fixed():
    previous = [_f("Missing CSP"), _f("Weak TLS", "TLS")]
    current = [_f("Missing CSP"), _f("CORS reflects origin", "CORS")]

    annotated, fixed, summary = diff_findings(previous, current)

    by_title = {f["title"]: f["regression"] for f in annotated}
    assert by_title["Missing CSP"] == "recurring"
    assert by_title["CORS reflects origin"] == "new"
    assert [f["title"] for f in fixed] == ["Weak TLS"]
    assert summary == {"new": 1, "recurring": 1, "fixed": 1}


def test_diff_first_scan_all_new():
    current = [_f("A"), _f("B")]
    annotated, fixed, summary = diff_findings([], current)
    assert all(f["regression"] == "new" for f in annotated)
    assert fixed == []
    assert summary["new"] == 2
