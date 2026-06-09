"""Tests for the scope guard — the safety brake."""

from __future__ import annotations

import importlib

import pytest

from redhive import scope


@pytest.fixture(autouse=True)
def _reset_authorized():
    scope._authorized_hosts.clear()
    yield
    scope._authorized_hosts.clear()


def test_practice_hosts_allowed():
    assert scope.is_allowed("http://localhost:3000/login")
    assert scope.is_allowed("juiceshop")
    assert scope.is_allowed("http://127.0.0.1:8000")


def test_unknown_host_refused():
    assert not scope.is_allowed("https://example.com")
    with pytest.raises(scope.ScopeError):
        scope.assert_allowed("https://example.com")


def test_authorize_host_grants_access():
    assert not scope.is_allowed("https://customer.example")
    scope.authorize_host("https://customer.example/path")
    assert scope.is_allowed("https://customer.example/anything")


def test_host_extraction():
    assert scope.host_for("https://user:pass@Example.COM:443/x") == "example.com"
    assert scope.host_for("localhost:3000") == "localhost"
    assert scope.host_for("") == ""
