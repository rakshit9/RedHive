"""API integration tests — auth, multi-tenancy isolation, scan authorization.

These cover the security-critical paths but never run a real engagement (a scan
is only *enqueued*; the worker is not started), so no LLM calls are made.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


def _auth(key: str) -> dict:
    return {"authorization": f"Bearer {key}"}


# --------------------------------------------------------------------------- #
# Auth                                                                        #
# --------------------------------------------------------------------------- #


def test_signup_returns_token_and_key(client: TestClient):
    r = client.post("/auth/signup", json={"org_name": "Acme", "email": "a@acme.com", "password": "password123"})
    assert r.status_code == 201
    body = r.json()
    assert body["api_key"].startswith("rh_")
    assert body["token"]


def test_duplicate_email_rejected(client: TestClient):
    payload = {"org_name": "Acme", "email": "dup@acme.com", "password": "password123"}
    assert client.post("/auth/signup", json=payload).status_code == 201
    assert client.post("/auth/signup", json=payload).status_code == 409


def test_login_flow(client: TestClient):
    client.post("/auth/signup", json={"org_name": "Acme", "email": "l@acme.com", "password": "password123"})
    ok = client.post("/auth/login", json={"email": "l@acme.com", "password": "password123"})
    assert ok.status_code == 200 and ok.json()["token"]
    bad = client.post("/auth/login", json={"email": "l@acme.com", "password": "wrong"})
    assert bad.status_code == 401


def test_protected_endpoint_requires_auth(client: TestClient):
    assert client.get("/scans").status_code == 401
    assert client.get("/scans", headers=_auth("rh_bogus_key")).status_code == 401


def test_api_key_cannot_manage_keys(client: TestClient, org_key: str):
    # Key management is session-only; an API key must be refused (403).
    assert client.get("/auth/keys", headers=_auth(org_key)).status_code == 403


# --------------------------------------------------------------------------- #
# Scan authorization                                                          #
# --------------------------------------------------------------------------- #


def test_practice_target_scan_enqueues(client: TestClient, org_key: str):
    r = client.post("/scans", json={"target": "http://localhost:3000"}, headers=_auth(org_key))
    assert r.status_code == 201
    assert r.json()["status"] == "queued"


def test_unregistered_host_refused(client: TestClient, org_key: str):
    r = client.post("/scans", json={"target": "https://notmine.example"}, headers=_auth(org_key))
    assert r.status_code == 403
    assert "not registered" in r.json()["detail"]


def test_unverified_host_refused(client: TestClient, org_key: str):
    # Register but do NOT verify -> still refused.
    client.post("/targets", json={"host": "notmine.example"}, headers=_auth(org_key))
    r = client.post("/scans", json={"target": "https://notmine.example"}, headers=_auth(org_key))
    assert r.status_code == 403
    assert "not yet verified" in r.json()["detail"]


# --------------------------------------------------------------------------- #
# Multi-tenancy isolation                                                     #
# --------------------------------------------------------------------------- #


def test_orgs_cannot_see_each_others_scans(client: TestClient):
    a = client.post("/auth/signup", json={"org_name": "A", "email": "a@x.com", "password": "password123"}).json()["api_key"]
    b = client.post("/auth/signup", json={"org_name": "B", "email": "b@x.com", "password": "password123"}).json()["api_key"]

    sid = client.post("/scans", json={"target": "http://localhost:3000"}, headers=_auth(a)).json()["scan_id"]

    # Org A sees its scan; org B does not.
    assert client.get(f"/scans/{sid}", headers=_auth(a)).status_code == 200
    assert client.get(f"/scans/{sid}", headers=_auth(b)).status_code == 404
    assert client.get("/scans", headers=_auth(b)).json()["scans"] == []
