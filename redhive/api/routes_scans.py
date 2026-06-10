"""Scan routes — enqueue engagements and read results, all org-scoped.

The API only *enqueues* scans (writes a ``queued`` row); a separate worker runs
them (see ``redhive.worker``). The live log endpoint tails the persisted
``scan_logs`` rows, so it works no matter which process produced them.
"""

from __future__ import annotations

import asyncio
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from redhive import crypto, github_pr, report, repository as repo
from redhive.api.deps import AuthContext, require_auth
from redhive.config import settings
from redhive.database import session_scope
from redhive.db_models import ScanStatus
from redhive.scope import host_for, is_allowed

router = APIRouter(prefix="/scans", tags=["scans"])


class ScanRequest(BaseModel):
    target: str


def _org_can_scan(db, org_id: uuid.UUID, target: str) -> tuple[bool, str]:
    """Authorization gate for enqueuing a scan against ``target``.

    Allowed if the host is a built-in practice host, or the org has a *verified*
    target for it. Returns ``(ok, reason)``.
    """
    host = host_for(target)
    if not host:
        return False, "Could not parse a host from the target."
    if is_allowed(target):  # built-in practice allowlist
        return True, ""
    t = repo.get_target(db, org_id, host)
    if t is None:
        return False, f"Host {host!r} is not registered. Add it under /targets and verify ownership."
    if not t.verified:
        return False, f"Host {host!r} is registered but ownership is not yet verified."
    return True, ""


@router.post("", status_code=status.HTTP_201_CREATED)
def create_scan(req: ScanRequest, ctx: AuthContext = Depends(require_auth)) -> dict:
    with session_scope() as db:
        ok, reason = _org_can_scan(db, ctx.org_id, req.target)
        if not ok:
            raise HTTPException(status.HTTP_403_FORBIDDEN, reason)

        # Plan quota (free tier).
        if db.get(repo.Organization, ctx.org_id).plan == "free":  # type: ignore[union-attr]
            used = repo.monthly_scan_count(db, ctx.org_id)
            if used >= settings.free_monthly_scan_limit:
                raise HTTPException(
                    status.HTTP_402_PAYMENT_REQUIRED,
                    f"Free plan monthly scan limit ({settings.free_monthly_scan_limit}) reached. Upgrade to continue.",
                )

        host = host_for(req.target)
        target_row = repo.get_target(db, ctx.org_id, host)
        scan = repo.create_scan(
            db, org_id=ctx.org_id, target_url=req.target,
            target_id=target_row.id if target_row else None,
        )
        return {"scan_id": str(scan.id), "status": "queued"}


@router.get("")
def list_scans(ctx: AuthContext = Depends(require_auth), limit: int = Query(50, le=200)) -> dict:
    with session_scope() as db:
        scans = repo.list_scans(db, ctx.org_id, limit=limit)
        return {"scans": [repo.scan_to_dict(s) for s in scans]}


@router.get("/{scan_id}")
def get_scan(scan_id: uuid.UUID, ctx: AuthContext = Depends(require_auth)) -> dict:
    with session_scope() as db:
        scan = repo.get_scan(db, scan_id, org_id=ctx.org_id)
        if scan is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")
        data = repo.scan_to_dict(scan, include_children=True)
        data["log"] = [l.line for l in repo.get_logs(db, scan.id)]
        return data


@router.post("/{scan_id}/pr")
def open_pull_request(scan_id: uuid.UUID, ctx: AuthContext = Depends(require_auth)) -> dict:
    """Open a GitHub PR with this scan's remediation report + suggested fixes.

    Requires a connected GitHub integration and a finished scan with patches.
    """
    with session_scope() as db:
        scan = repo.get_scan(db, scan_id, org_id=ctx.org_id)
        if scan is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")
        if scan.status != ScanStatus.DONE:
            raise HTTPException(status.HTTP_409_CONFLICT, "Scan is not finished.")
        if not scan.patches:
            raise HTTPException(status.HTTP_409_CONFLICT, "This scan produced no patches to PR.")

        integ = repo.get_github_integration(db, ctx.org_id)
        if integ is None:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "No GitHub repository connected. Connect one under Integrations first.",
            )
        token = crypto.decrypt(integ.token_encrypted)
        repo_full_name, default_branch = integ.repo_full_name, integ.default_branch
        payload = repo.scan_to_dict(scan, include_children=True)

    if token is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Stored GitHub token could not be decrypted — please reconnect the repository.",
        )

    try:
        result = github_pr.open_remediation_pr(
            repo_full_name=repo_full_name,
            token=token,
            scan=payload,
            default_branch=default_branch,
        )
    except github_pr.GitHubError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return {"pr_url": result["pr_url"], "branch": result["branch"], "repo": repo_full_name}


@router.get("/{scan_id}/report")
def get_report(scan_id: uuid.UUID, ctx: AuthContext = Depends(require_auth), format: str = "markdown"):
    with session_scope() as db:
        scan = repo.get_scan(db, scan_id, org_id=ctx.org_id)
        if scan is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")
        payload = repo.scan_to_dict(scan, include_children=True)
    if format == "json":
        return report.render_json(payload)
    return PlainTextResponse(report.render_markdown(payload), media_type="text/markdown")


@router.get("/{scan_id}/log")
async def stream_log(scan_id: uuid.UUID, ctx: AuthContext = Depends(require_auth)) -> EventSourceResponse:
    # Authorize + existence check up front.
    with session_scope() as db:
        scan = repo.get_scan(db, scan_id, org_id=ctx.org_id)
        if scan is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found.")

    async def event_generator():
        last_seq = -1
        while True:
            # Pull any new log lines and the current status from the DB.
            await asyncio.sleep(0.5)
            with session_scope() as db:
                rows = repo.get_logs(db, scan_id, after_seq=last_seq)
                s = repo.get_scan(db, scan_id, org_id=ctx.org_id)
                status_val = s.status.value if s and s.status else "unknown"
            for row in rows:
                last_seq = max(last_seq, row.seq)
                yield {"event": "log", "data": row.line}
            if status_val in ("done", "failed", "canceled"):
                # Drain any final lines written between the two queries above.
                with session_scope() as db:
                    for row in repo.get_logs(db, scan_id, after_seq=last_seq):
                        last_seq = max(last_seq, row.seq)
                        yield {"event": "log", "data": row.line}
                yield {"event": "done", "data": status_val}
                return

    return EventSourceResponse(event_generator())
