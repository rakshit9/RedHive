"""Target routes — register a host, prove ownership, then it becomes scannable.

Flow:
    POST /targets            -> create (unverified) + return token & instructions
    POST /targets/{id}/verify-> run the DNS/HTTP probe; flips verified on success
    GET  /targets            -> list this org's targets
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from redhive import repository as repo, targets as ownership
from redhive.api.deps import AuthContext, require_auth
from redhive.config import settings
from redhive.database import session_scope
from redhive.db_models import VerificationMethod
from redhive.scope import host_for

router = APIRouter(prefix="/targets", tags=["targets"])


class CreateTargetRequest(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    display_name: str = Field(default="", max_length=255)
    method: VerificationMethod = VerificationMethod.DNS_TXT


def _instructions(host: str, token: str, method: VerificationMethod) -> dict:
    if method == VerificationMethod.DNS_TXT:
        return {
            "method": "dns_txt",
            "record_name": ownership.dns_record_name(host),
            "record_type": "TXT",
            "record_value": token,
            "hint": f"Add a TXT record at {ownership.dns_record_name(host)} with value '{token}', then call verify.",
        }
    return {
        "method": "http_file",
        "url": ownership.well_known_url(host),
        "file_contents": token,
        "hint": f"Serve '{token}' at {ownership.well_known_url(host)}, then call verify.",
    }


@router.post("", status_code=status.HTTP_201_CREATED)
def create_target(req: CreateTargetRequest, ctx: AuthContext = Depends(require_auth)) -> dict:
    host = host_for(req.host) or req.host.lower()

    # Practice hosts are pre-verified — no ownership proof needed.
    if host in settings.allowlist:
        with session_scope() as db:
            t = repo.upsert_target(
                db, org_id=ctx.org_id, host=host, display_name=req.display_name or host,
                method=VerificationMethod.PRACTICE, verification_token="",
            )
            t.verified = True
            from datetime import datetime, timezone
            t.verified_at = datetime.now(timezone.utc)
            db.flush()
            return {"target": repo.target_to_dict(t), "verification": None,
                    "message": "Practice target — pre-verified."}

    token = ownership.new_verification_token()
    with session_scope() as db:
        t = repo.upsert_target(
            db, org_id=ctx.org_id, host=host, display_name=req.display_name or host,
            method=req.method, verification_token=token,
        )
        return {
            "target": repo.target_to_dict(t),
            "verification": _instructions(host, token, req.method),
            "message": "Target created. Publish the verification token, then POST /targets/{id}/verify.",
        }


@router.post("/{target_id}/verify")
def verify_target(target_id: uuid.UUID, ctx: AuthContext = Depends(require_auth)) -> dict:
    with session_scope() as db:
        t = db.get(repo.Target, target_id)
        if t is None or t.org_id != ctx.org_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Target not found.")
        if t.verified:
            return {"verified": True, "target": repo.target_to_dict(t)}

        method = t.method.value if hasattr(t.method, "value") else str(t.method)
        ok = ownership.check_ownership(t.host, t.verification_token, method)
        if not ok:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"Ownership proof not found for {t.host!r}. Publish the token and retry.",
            )
        from datetime import datetime, timezone
        t.verified = True
        t.verified_at = datetime.now(timezone.utc)
        db.flush()
        return {"verified": True, "target": repo.target_to_dict(t)}


@router.get("")
def list_targets(ctx: AuthContext = Depends(require_auth)) -> dict:
    with session_scope() as db:
        return {"targets": [repo.target_to_dict(t) for t in repo.list_targets(db, ctx.org_id)]}
