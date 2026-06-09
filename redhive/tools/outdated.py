"""Outdated / EOL software heuristic.

Consumes the dict produced by :func:`redhive.tools.fingerprint.fingerprint`
(keys ``server``, ``x_powered_by``, ``technologies``), parses version-like
tokens out of the values, and flags products at or below a small built-in
"known-old" threshold table. No network calls.
"""

from __future__ import annotations

import re

from redhive.models import Finding, Severity

# Matches "nginx/1.14.0", "Apache/2.2.15", "PHP/5.6", "OpenSSL/1.0.1f".
_VERSION_RE = re.compile(r"([A-Za-z][A-Za-z0-9 .+_-]*?)[/ ]v?(\d+(?:\.\d+){0,3})")

# product (lowercased) -> (max known-old version tuple, note, severity).
# A detected version <= the threshold is flagged. These are deliberately
# conservative, illustrative thresholds for a practice platform.
_KNOWN_OLD: dict[str, tuple[tuple[int, ...], str, Severity]] = {
    "nginx": (
        (1, 20, 0),
        "nginx <= 1.20.x is past mainline; upgrade to a current stable "
        "release for security fixes.",
        Severity.MEDIUM,
    ),
    "apache": (
        (2, 4, 50),
        "Apache httpd <= 2.4.50 includes versions affected by path-traversal "
        "/ RCE CVEs (e.g. CVE-2021-41773); upgrade.",
        Severity.MEDIUM,
    ),
    "openssl": (
        (1, 0, 2),
        "OpenSSL 1.0.x is end-of-life and unpatched; upgrade to a supported "
        "1.1.1+ / 3.x branch.",
        Severity.MEDIUM,
    ),
    "php": (
        (7, 4, 99),
        "PHP <= 7.4 is end-of-life and no longer receiving security patches; "
        "upgrade to a supported 8.x release.",
        Severity.MEDIUM,
    ),
    "jquery": (
        (3, 4, 99),
        "jQuery <= 3.4.x contains known XSS issues (e.g. CVE-2020-11022/11023); "
        "upgrade to 3.5+.",
        Severity.MEDIUM,
    ),
    "bootstrap": (
        (3, 999, 999),
        "Bootstrap 3.x is end-of-life and has known XSS issues; upgrade to "
        "4.x / 5.x.",
        Severity.LOW,
    ),
    "openssh": (
        (7, 9, 99),
        "OpenSSH <= 7.9 is dated; upgrade for accumulated security fixes.",
        Severity.LOW,
    ),
    "iis": (
        (8, 999, 999),
        "Microsoft IIS <= 8.x runs on end-of-life Windows Server versions; "
        "upgrade the platform.",
        Severity.MEDIUM,
    ),
}

# Normalize a few common product aliases to the table keys above.
_ALIASES: dict[str, str] = {
    "apache": "apache",
    "httpd": "apache",
    "microsoft-iis": "iis",
    "iis": "iis",
}


def _to_tuple(version: str) -> tuple[int, ...]:
    """Parse a dotted version string into an int tuple (best-effort)."""
    parts: list[int] = []
    for chunk in version.split("."):
        m = re.match(r"\d+", chunk)
        parts.append(int(m.group()) if m else 0)
    return tuple(parts)


def _normalize(product: str) -> str:
    """Map a raw product label to a known table key (lowercased)."""
    key = product.strip().lower()
    return _ALIASES.get(key, key)


def check_outdated(fingerprint: dict) -> list[Finding]:
    """Flag clearly old / EOL software from a fingerprint dict.

    Parses version tokens out of ``server``, ``x_powered_by`` and each entry
    of ``technologies``, then compares against a built-in threshold table.
    Returns one ``Finding`` per outdated product. No network calls; never
    raises (a malformed dict yields an empty list).
    """
    findings: list[Finding] = []
    if not isinstance(fingerprint, dict):
        return findings

    # Collect all candidate strings that may carry version info.
    blobs: list[str] = []
    for key in ("server", "x_powered_by"):
        val = fingerprint.get(key)
        if isinstance(val, str) and val:
            blobs.append(val)
    techs = fingerprint.get("technologies")
    if isinstance(techs, (list, tuple)):
        blobs.extend(t for t in techs if isinstance(t, str) and t)

    # Dedupe (product, version) so the same hint in two places isn't double-reported.
    seen: set[tuple[str, str]] = set()

    for blob in blobs:
        for raw_product, raw_version in _VERSION_RE.findall(blob):
            product = _normalize(raw_product)
            entry = _KNOWN_OLD.get(product)
            if entry is None:
                continue

            threshold, note, base_severity = entry
            detected = _to_tuple(raw_version)
            # Pad to equal length for a fair tuple comparison.
            width = max(len(detected), len(threshold))
            det_p = detected + (0,) * (width - len(detected))
            thr_p = threshold + (0,) * (width - len(threshold))
            if det_p > thr_p:
                continue  # newer than our known-old threshold

            dedupe_key = (product, raw_version)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)

            # Downgrade to LOW when only a single version component is known
            # (e.g. "PHP/5") -- the match is less certain.
            severity = base_severity
            if len(detected) < 2:
                severity = Severity.LOW

            findings.append(
                Finding(
                    title=f"Outdated software: {raw_product.strip()} {raw_version}",
                    category="Outdated Software",
                    severity=severity,
                    target=fingerprint.get("server") or "(fingerprint)",
                    description=note,
                    evidence=(
                        f"Fingerprint reported '{blob}' -> detected "
                        f"{raw_product.strip()} version {raw_version}."
                    ),
                    reproduction=[
                        "Run the fingerprint tool against the target.",
                        f"Observe the version banner: {raw_product.strip()} "
                        f"{raw_version}.",
                        "Compare against the vendor's supported releases.",
                    ],
                    discovered_by="tools",
                )
            )

    return findings
