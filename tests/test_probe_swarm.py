"""Tests for the parallel probe-agent swarm (map-reduce fan-out)."""

from __future__ import annotations

from langgraph.types import Send

from redhive.agents import probe


def _surface(n_endpoints: int, with_params: int):
    return [
        {
            "url": f"http://localhost:8000/area{i}",
            "params": ["q", "id"] if i < with_params else [],
            "has_form": i < with_params,
            "method": "GET",
        }
        for i in range(n_endpoints)
    ]


def test_plan_probes_scales_with_surface():
    state = {
        "target": "http://localhost:8000",
        "attack_surface": _surface(12, with_params=10),
        "deep_pass": False,
        "fingerprint": {},
    }
    out = probe.plan_probes(state)
    tasks = out["probe_tasks"]
    kinds = {t["kind"] for t in tasks}

    # First-pass caps: 8 endpoints x2 per-endpoint + 3 host + 8 inputs x4.
    assert out["agents_dispatched"] == len(tasks)
    assert out["agents_dispatched"] >= 40  # genuinely a swarm
    assert {"headers", "cors", "tls", "exposed_files", "outdated", "xss", "sqli", "open_redirect", "csrf"} >= kinds


def test_deep_pass_widens_coverage():
    surface = _surface(25, with_params=25)
    shallow = probe.plan_probes({"target": "t", "attack_surface": surface, "deep_pass": False, "fingerprint": {}})
    deep = probe.plan_probes({"target": "t", "attack_surface": surface, "deep_pass": True, "fingerprint": {}})
    assert deep["agents_dispatched"] > shallow["agents_dispatched"]


def test_fan_out_emits_one_send_per_task():
    state = {"probe_tasks": [{"kind": "headers", "url": "u"}, {"kind": "tls", "target": "t"}]}
    sends = probe.fan_out_probes(state)
    assert len(sends) == 2
    assert all(isinstance(s, Send) and s.node == "probe" for s in sends)


def test_probe_runs_check_and_returns_findings(monkeypatch):
    class _F:
        def model_dump(self):
            return {"title": "X", "severity": "low"}

    monkeypatch.setattr(probe, "_run_check", lambda task: [_F(), _F()])
    out = probe.probe({"kind": "headers", "url": "http://localhost:8000"})
    assert len(out["raw_findings"]) == 2
    assert out["log"] and "2 finding" in out["log"][0]


def test_probe_isolates_failure(monkeypatch):
    def boom(task):
        raise RuntimeError("network down")

    monkeypatch.setattr(probe, "_run_check", boom)
    out = probe.probe({"kind": "xss", "url": "http://localhost:8000"})
    # A crashing probe degrades to a log line, never raises.
    assert "raw_findings" not in out or out.get("raw_findings") == []
    assert out["log"]


def test_aggregate_hands_raw_findings_forward():
    out = probe.aggregate({"raw_findings": [{"title": "A"}, {"title": "B"}], "agents_dispatched": 5})
    assert out["findings"] == [{"title": "A"}, {"title": "B"}]
    assert "5 probe agent" in out["log"][0]
