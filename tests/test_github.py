"""Tests for the GitHub PR feature: crypto, the PR flow (mocked), and endpoints."""

from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

from redhive import crypto, github_pr


# --------------------------------------------------------------------------- #
# Crypto                                                                      #
# --------------------------------------------------------------------------- #


def test_crypto_roundtrip():
    token = "github_pat_secret_value_123"
    enc = crypto.encrypt(token)
    assert enc != token
    assert crypto.decrypt(enc) == token


def test_crypto_decrypt_garbage_returns_none():
    assert crypto.decrypt("not-a-valid-token") is None


# --------------------------------------------------------------------------- #
# github_pr against a mocked GitHub API                                       #
# --------------------------------------------------------------------------- #


def _install_mock(monkeypatch, handler):
    real_client = httpx.Client  # capture before patching to avoid self-recursion

    def factory(*_a, **kw):
        return real_client(
            base_url=kw.get("base_url", "https://api.github.com"),
            headers=kw.get("headers"),
            timeout=kw.get("timeout", 10),
            transport=httpx.MockTransport(handler),
        )

    monkeypatch.setattr(github_pr.httpx, "Client", factory)


def test_validate_repo(monkeypatch):
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/repos/acme/web"
        return httpx.Response(200, json={"default_branch": "trunk"})

    _install_mock(monkeypatch, handler)
    assert github_pr.validate_repo("acme/web", "tok") == "trunk"


def test_validate_repo_404(monkeypatch):
    _install_mock(monkeypatch, lambda req: httpx.Response(404, json={"message": "Not Found"}))
    with pytest.raises(github_pr.GitHubError):
        github_pr.validate_repo("acme/missing", "tok")


def test_open_remediation_pr(monkeypatch):
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        path, method = req.url.path, req.method
        seen.append(f"{method} {path}")
        if method == "GET" and path.endswith("/git/ref/heads/main"):
            return httpx.Response(200, json={"object": {"sha": "base123"}})
        if method == "GET" and "/git/commits/base123" in path:
            return httpx.Response(200, json={"tree": {"sha": "tree123"}})
        if method == "POST" and path.endswith("/git/trees"):
            return httpx.Response(201, json={"sha": "newtree"})
        if method == "POST" and path.endswith("/git/commits"):
            return httpx.Response(201, json={"sha": "newcommit"})
        if method == "POST" and path.endswith("/git/refs"):
            return httpx.Response(201, json={})
        if method == "POST" and path.endswith("/pulls"):
            return httpx.Response(201, json={"html_url": "https://github.com/acme/web/pull/7"})
        return httpx.Response(500, json={"message": f"unexpected {method} {path}"})

    _install_mock(monkeypatch, handler)

    scan = {
        "scan_id": "abcdef123456",
        "target": "https://acme.example",
        "risk_score": 42,
        "findings": [{"title": "Missing CSP", "category": "Security Headers", "severity": "medium"}],
        "patches": [{"finding_title": "Missing CSP", "file_hint": "nginx.conf", "diff": "add_header CSP ...", "explanation": "x"}],
        "attack_chains": [],
    }
    result = github_pr.open_remediation_pr(
        repo_full_name="acme/web", token="tok", scan=scan, default_branch="main"
    )
    assert result["pr_url"] == "https://github.com/acme/web/pull/7"
    assert result["branch"] == "redhive/remediation-abcdef12"
    # The full Git Data flow was exercised in order.
    assert any("POST /repos/acme/web/pulls" in s for s in seen)
    assert any("/git/trees" in s for s in seen)


def test_open_pr_surfaces_github_error(monkeypatch):
    _install_mock(monkeypatch, lambda req: httpx.Response(404, json={"message": "no branch"}))
    with pytest.raises(github_pr.GitHubError):
        github_pr.open_remediation_pr(
            repo_full_name="acme/web", token="tok",
            scan={"scan_id": "x", "patches": []}, default_branch="main",
        )


# --------------------------------------------------------------------------- #
# Integration endpoints                                                       #
# --------------------------------------------------------------------------- #


def _signup(client: TestClient):
    r = client.post(
        "/auth/signup",
        json={"org_name": "Gh Org", "email": "gh@org.com", "password": "password123"},
    ).json()
    return r["token"], r["api_key"]


def test_connect_requires_session(client: TestClient):
    _, key = _signup(client)
    # API key (not a session) must be refused on this session-only endpoint.
    r = client.post(
        "/integrations/github",
        json={"repo_full_name": "acme/web", "token": "tok-123456"},
        headers={"authorization": f"Bearer {key}"},
    )
    assert r.status_code == 403


def test_connect_and_list(client: TestClient, monkeypatch):
    monkeypatch.setattr(github_pr, "validate_repo", lambda repo, token: "main")
    token, _ = _signup(client)
    h = {"authorization": f"Bearer {token}"}

    r = client.post("/integrations/github", json={"repo_full_name": "acme/web", "token": "tok-123456"}, headers=h)
    assert r.status_code == 201, r.text

    lst = client.get("/integrations/github", headers=h).json()["integrations"]
    assert len(lst) == 1 and lst[0]["repo_full_name"] == "acme/web"


def test_open_pr_on_unfinished_scan_409(client: TestClient):
    _, key = _signup(client)
    h = {"authorization": f"Bearer {key}"}
    sid = client.post("/scans", json={"target": "http://localhost:3000"}, headers=h).json()["scan_id"]
    # Scan is queued (worker not running in tests) -> 409 not finished.
    r = client.post(f"/scans/{sid}/pr", headers=h)
    assert r.status_code == 409
