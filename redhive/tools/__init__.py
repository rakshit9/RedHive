"""Scan tools: deterministic probes the agents call to gather raw signal.

Each tool fails soft (never raises on network errors) and returns the
shared models from ``redhive.models`` so every consumer speaks the same
contract.
"""

from __future__ import annotations

from redhive.tools.crawl import crawl
from redhive.tools.exposed_files import check_exposed_files
from redhive.tools.fingerprint import fingerprint
from redhive.tools.injection import test_sqli, test_xss
from redhive.tools.security_headers import check_security_headers
from redhive.tools.tls import check_tls

__all__ = [
    "crawl",
    "check_security_headers",
    "check_tls",
    "check_exposed_files",
    "fingerprint",
    "test_xss",
    "test_sqli",
]
