"""Tests for content/path discovery (probes mocked — no real network)."""

from __future__ import annotations

import httpx

from redhive.tools import discover


def _mock(monkeypatch, handler):
    real = httpx.Client

    def factory(*_a, **kw):
        return real(
            timeout=kw.get("timeout", 5),
            headers=kw.get("headers"),
            follow_redirects=kw.get("follow_redirects", False),
            transport=httpx.MockTransport(handler),
        )

    monkeypatch.setattr(discover.httpx, "Client", factory)


def test_discovers_handled_paths(monkeypatch):
    # /login + /admin "exist"; everything else 404s.
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path in ("/login", "/admin"):
            return httpx.Response(200, text="ok")
        return httpx.Response(404)

    _mock(monkeypatch, handler)
    eps = discover.discover_paths("http://localhost:8780")
    paths = {httpx.URL(e.url).path for e in eps}
    assert "/login" in paths and "/admin" in paths
    assert all("/search" not in p for p in paths)  # 404s excluded


def test_parameterized_paths_carry_params(monkeypatch):
    _mock(monkeypatch, lambda req: httpx.Response(200))
    eps = discover.discover_paths("http://localhost:8780")
    # Something parameterized (e.g. /search?q=) should expose its param name.
    assert any(e.params for e in eps)


def test_transport_errors_are_skipped(monkeypatch):
    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    _mock(monkeypatch, handler)
    assert discover.discover_paths("http://localhost:8780") == []
