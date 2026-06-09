"""Auth & account routes — signup, login, profile, API-key management."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from redhive import repository as repo
from redhive.api.deps import AuthContext, require_session
from redhive.database import session_scope
from redhive.security import (
    generate_api_key,
    hash_password,
    issue_session_token,
    verify_password,
)

router = APIRouter(tags=["auth"])

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(name: str) -> str:
    base = _SLUG_RE.sub("-", name.lower()).strip("-") or "org"
    return base[:60]


# --------------------------------------------------------------------------- #
# Schemas                                                                     #
# --------------------------------------------------------------------------- #


class SignupRequest(BaseModel):
    org_name: str = Field(min_length=1, max_length=200)
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    token: str
    org_id: str
    api_key: str | None = None  # returned only at signup, shown once


class CreateKeyRequest(BaseModel):
    name: str = Field(default="default", max_length=120)


# --------------------------------------------------------------------------- #
# Routes                                                                      #
# --------------------------------------------------------------------------- #


@router.post("/auth/signup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def signup(req: SignupRequest) -> TokenResponse:
    """Create an organization, its owner user, and a first API key."""
    with session_scope() as db:
        if repo.get_user_by_email(db, req.email) is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered.")

        # Ensure a unique org slug.
        base_slug = _slugify(req.org_name)
        slug, n = base_slug, 1
        while repo.get_org_by_slug(db, slug) is not None:
            n += 1
            slug = f"{base_slug}-{n}"

        org = repo.create_organization(db, name=req.org_name, slug=slug)
        user = repo.create_user(
            db, org_id=org.id, email=req.email, password_hash=hash_password(req.password)
        )
        full_key, prefix, key_hash = generate_api_key()
        repo.create_api_key(db, org_id=org.id, name="default", prefix=prefix, key_hash=key_hash)

        token = issue_session_token(str(user.id), str(org.id))
        return TokenResponse(token=token, org_id=str(org.id), api_key=full_key)


@router.post("/auth/login", response_model=TokenResponse)
def login(req: LoginRequest) -> TokenResponse:
    with session_scope() as db:
        user = repo.get_user_by_email(db, req.email)
        if user is None or not verify_password(req.password, user.password_hash):
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password.")
        token = issue_session_token(str(user.id), str(user.org_id))
        return TokenResponse(token=token, org_id=str(user.org_id))


@router.get("/auth/me")
def me(ctx: AuthContext = Depends(require_session)) -> dict:
    with session_scope() as db:
        org = db.get(repo.Organization, ctx.org_id)
        user = db.get(repo.User, ctx.user_id) if ctx.user_id else None
        return {
            "org_id": str(ctx.org_id),
            "org_name": org.name if org else None,
            "plan": org.plan if org else None,
            "email": user.email if user else None,
        }


@router.get("/auth/keys")
def list_keys(ctx: AuthContext = Depends(require_session)) -> dict:
    with session_scope() as db:
        keys = repo.list_api_keys(db, ctx.org_id)
        return {
            "keys": [
                {
                    "id": str(k.id),
                    "name": k.name,
                    "prefix": k.prefix,
                    "created_at": k.created_at.isoformat() if k.created_at else None,
                    "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                    "revoked": k.revoked_at is not None,
                }
                for k in keys
            ]
        }


@router.post("/auth/keys", status_code=status.HTTP_201_CREATED)
def create_key(req: CreateKeyRequest, ctx: AuthContext = Depends(require_session)) -> dict:
    """Mint a new API key. The full key is returned ONCE — store it now."""
    with session_scope() as db:
        full_key, prefix, key_hash = generate_api_key()
        key = repo.create_api_key(db, org_id=ctx.org_id, name=req.name, prefix=prefix, key_hash=key_hash)
        return {"id": str(key.id), "name": key.name, "prefix": prefix, "api_key": full_key}
