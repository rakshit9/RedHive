"""Open remediation pull requests on a connected GitHub repository.

This is the "close the loop" feature: after a scan, RedHive can open a PR on the
customer's repo containing a reviewable remediation report (the same Markdown the
API serves) plus the AI-drafted fixes for each confirmed finding. A developer
reviews and merges — the finding moves from "reported" to "being fixed" without
anyone copy-pasting.

We commit through the Git Data API (blob → tree → commit → ref) so all files
land in a single clean commit, then open the PR. Everything is best-effort and
raises ``GitHubError`` with a human-readable message on failure; the API layer
turns that into a 4xx.
"""

from __future__ import annotations

import re
from typing import Any

import httpx

from redhive import report

_API = "https://api.github.com"
_TIMEOUT = 20.0


class GitHubError(RuntimeError):
    """A GitHub API call failed (auth, missing repo, permissions, etc.)."""


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40] or "finding"


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _raise(resp: httpx.Response, action: str) -> None:
    msg = action
    try:
        body = resp.json()
        if isinstance(body, dict) and body.get("message"):
            msg = f"{action}: {body['message']}"
    except Exception:  # noqa: BLE001
        pass
    raise GitHubError(f"{msg} (HTTP {resp.status_code})")


def validate_repo(repo_full_name: str, token: str) -> str:
    """Confirm the token can access the repo; return its default branch.

    Raises ``GitHubError`` if the repo is missing or the token lacks access —
    so we never store a credential we can't actually use.
    """
    with httpx.Client(base_url=_API, headers=_headers(token), timeout=_TIMEOUT) as gh:
        resp = gh.get(f"/repos/{repo_full_name}")
        if resp.status_code == 404:
            raise GitHubError(f"Repo {repo_full_name!r} not found or token lacks access.")
        if resp.status_code == 401:
            raise GitHubError("GitHub token is invalid or expired.")
        if resp.status_code != 200:
            _raise(resp, "Could not validate repository")
        return resp.json().get("default_branch", "main")


def _build_files(scan: dict[str, Any]) -> dict[str, str]:
    """Map the scan into the files the PR will add/update.

    - A single comprehensive Markdown remediation report (reuses the API's
      report renderer), placed under ``redhive-findings/``.
    - One file per drafted patch so each fix is a reviewable unit.
    """
    short = str(scan.get("scan_id", "scan"))[:8]
    files: dict[str, str] = {
        f"redhive-findings/scan-{short}.md": report.render_markdown(scan),
    }
    for i, patch in enumerate(scan.get("patches", []) or [], 1):
        title = _slug(str(patch.get("finding_title", f"fix-{i}")))
        body = (
            f"# Suggested fix: {patch.get('finding_title', '')}\n\n"
            f"{patch.get('file_hint', '')}\n\n{patch.get('diff', '')}\n\n"
            f"_{patch.get('explanation', '')}_\n"
        )
        files[f"redhive-findings/patches/{i:02d}-{title}.md"] = body
    return files


def open_remediation_pr(
    *,
    repo_full_name: str,
    token: str,
    scan: dict[str, Any],
    default_branch: str = "main",
) -> dict[str, str]:
    """Open a PR with the scan's remediation report + fixes. Returns
    ``{"pr_url", "branch", "files"}``."""
    short = str(scan.get("scan_id", "scan"))[:8]
    branch = f"redhive/remediation-{short}"
    files = _build_files(scan)
    findings = scan.get("findings", []) or []
    risk = scan.get("risk_score")

    with httpx.Client(base_url=_API, headers=_headers(token), timeout=_TIMEOUT) as gh:
        # Resolve the base branch head commit.
        ref = gh.get(f"/repos/{repo_full_name}/git/ref/heads/{default_branch}")
        if ref.status_code != 200:
            _raise(ref, f"Could not read branch {default_branch!r}")
        base_sha = ref.json()["object"]["sha"]

        base_commit = gh.get(f"/repos/{repo_full_name}/git/commits/{base_sha}")
        if base_commit.status_code != 200:
            _raise(base_commit, "Could not read base commit")
        base_tree = base_commit.json()["tree"]["sha"]

        # Build a tree with our files on top of the base tree.
        tree_entries = [
            {"path": path, "mode": "100644", "type": "blob", "content": content}
            for path, content in files.items()
        ]
        tree = gh.post(
            f"/repos/{repo_full_name}/git/trees",
            json={"base_tree": base_tree, "tree": tree_entries},
        )
        if tree.status_code != 201:
            _raise(tree, "Could not create tree")
        new_tree = tree.json()["sha"]

        commit = gh.post(
            f"/repos/{repo_full_name}/git/commits",
            json={
                "message": f"RedHive: remediation for scan {short} ({len(findings)} findings)",
                "tree": new_tree,
                "parents": [base_sha],
            },
        )
        if commit.status_code != 201:
            _raise(commit, "Could not create commit")
        new_commit = commit.json()["sha"]

        # Create the branch ref pointing at our new commit.
        new_ref = gh.post(
            f"/repos/{repo_full_name}/git/refs",
            json={"ref": f"refs/heads/{branch}", "sha": new_commit},
        )
        if new_ref.status_code not in (200, 201):
            _raise(new_ref, f"Could not create branch {branch!r}")

        # Open the PR.
        body = _pr_body(scan, findings, risk)
        pr = gh.post(
            f"/repos/{repo_full_name}/pulls",
            json={
                "title": f"🛡️ RedHive remediation — {len(findings)} finding(s) on {scan.get('target', '')}",
                "head": branch,
                "base": default_branch,
                "body": body,
            },
        )
        if pr.status_code != 201:
            _raise(pr, "Could not open pull request")
        return {"pr_url": pr.json()["html_url"], "branch": branch, "files": str(len(files))}


def _pr_body(scan: dict[str, Any], findings: list[dict[str, Any]], risk: Any) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    summary = ", ".join(f"{n} {s}" for s, n in counts.items()) or "no findings"
    lines = [
        "This PR was opened automatically by **RedHive** after an authorized scan.",
        "",
        f"- **Target:** `{scan.get('target', '')}`",
        f"- **Risk score:** {risk}/100" if risk is not None else "",
        f"- **Findings:** {summary}",
        "",
        "It adds a full remediation report under `redhive-findings/` and a "
        "suggested fix per finding. Review the fixes, apply what's relevant, "
        "and merge. Re-scan to confirm the findings are resolved.",
        "",
        "> ⚠️ Suggested fixes are AI-drafted — review before merging.",
    ]
    return "\n".join(l for l in lines if l != "")
