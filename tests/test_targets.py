"""Tests for target ownership verification (probes mocked — no real DNS/HTTP)."""

from __future__ import annotations

from redhive import targets


def test_token_and_record_helpers():
    token = targets.new_verification_token()
    assert token.startswith("redhive-verify=")
    assert targets.dns_record_name("acme.com").endswith(".acme.com")
    assert targets.well_known_url("acme.com").endswith("/.well-known/redhive-verify.txt")


def test_check_ownership_dns(monkeypatch):
    monkeypatch.setattr(targets, "verify_dns_txt", lambda h, t: True)
    assert targets.check_ownership("acme.com", "tok", "dns_txt")
    monkeypatch.setattr(targets, "verify_dns_txt", lambda h, t: False)
    assert not targets.check_ownership("acme.com", "tok", "dns_txt")


def test_check_ownership_http(monkeypatch):
    monkeypatch.setattr(targets, "verify_http_file", lambda h, t: True)
    assert targets.check_ownership("acme.com", "tok", "http_file")


def test_check_ownership_unknown_method():
    assert not targets.check_ownership("acme.com", "tok", "bogus")
