"""Integration routes — connect a GitHub repo for auto-remediation PRs."""

from __future__ import annotations

import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from redhive import crypto, github_pr, repository as repo
from redhive.api.deps import AuthContext, require_session
from redhive.database import session_scope

router = APIRouter(prefix="/integrations/github", tags=["integrations"])

_REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")


class ConnectRequest(BaseModel):
    repo_full_name: str = Field(min_length=3, max_length=255, description="owner/repo")
    token: str = Field(min_length=10, description="GitHub access token with repo scope")


def _integration_dict(i) -> dict:  # noqa: ANN001
    return {
        "id": str(i.id),
        "repo_full_name": i.repo_full_name,
        "default_branch": i.default_branch,
        "created_at": i.created_at.isoformat() if i.created_at else None,
    }


@router.post("", status_code=status.HTTP_201_CREATED)
def connect(req: ConnectRequest, ctx: AuthContext = Depends(require_session)) -> dict:
    """Connect a repo. We validate the token against GitHub before storing it
    (encrypted), so a bad credential is rejected up front."""
    if not _REPO_RE.match(req.repo_full_name):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "repo_full_name must be 'owner/repo'.")
    try:
        default_branch = github_pr.validate_repo(req.repo_full_name, req.token)
    except github_pr.GitHubError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    with session_scope() as db:
        integ = repo.upsert_github_integration(
            db,
            org_id=ctx.org_id,
            repo_full_name=req.repo_full_name,
            token_encrypted=crypto.encrypt(req.token),
            default_branch=default_branch,
        )
        return {"integration": _integration_dict(integ), "message": "Repository connected."}


@router.get("")
def list_integrations(ctx: AuthContext = Depends(require_session)) -> dict:
    with session_scope() as db:
        return {
            "integrations": [
                _integration_dict(i) for i in repo.list_github_integrations(db, ctx.org_id)
            ]
        }


@router.delete("/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def disconnect(integration_id: uuid.UUID, ctx: AuthContext = Depends(require_session)) -> None:
    with session_scope() as db:
        if not repo.delete_github_integration(db, ctx.org_id, integration_id):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Integration not found.")
