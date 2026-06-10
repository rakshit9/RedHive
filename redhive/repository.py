"""Repository layer — all database reads/writes go through here.

The API and the worker share this module so query logic and the ORM->dict
serialization live in exactly one place. Every function takes an explicit
``Session`` (callers own the transaction via ``redhive.database.session_scope``)
and every customer-scoped query is filtered by ``org_id`` so tenants can never
see each other's data.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, selectinload

from redhive.db_models import (
    ApiKey,
    AttackChain,
    Finding,
    GitHubIntegration,
    Organization,
    Patch,
    Scan,
    ScanLog,
    ScanStatus,
    Target,
    User,
    UserRole,
    VerificationMethod,
)


def _uid(value: str | uuid.UUID) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# Serializers (ORM -> plain dict for the API and agents)                      #
# --------------------------------------------------------------------------- #


def finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": str(f.id),
        "title": f.title,
        "category": f.category,
        "severity": f.severity,
        "target": f.target,
        "description": f.description,
        "evidence": f.evidence,
        "reproduction": f.reproduction or [],
        "remediation": f.remediation,
        "confirmed": f.confirmed,
        "false_positive": f.false_positive,
        "discovered_by": f.discovered_by,
        "regression": f.regression,
    }


def scan_to_dict(s: Scan, *, include_children: bool = False) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for f in s.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    data: dict[str, Any] = {
        "scan_id": str(s.id),
        "org_id": str(s.org_id),
        "target": s.target_url,
        "status": s.status.value if isinstance(s.status, ScanStatus) else s.status,
        "risk_score": s.risk_score,
        "regression_summary": s.regression_summary,
        "severity_counts": counts,
        "findings_count": len(s.findings),
        "error": s.error,
        "usage": {
            "tokens": s.tokens_used,
            "llm_calls": s.llm_calls,
            "cost_usd": s.cost_usd,
        },
        "created_at": s.created_at.isoformat() if s.created_at else None,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "finished_at": s.finished_at.isoformat() if s.finished_at else None,
    }
    if include_children:
        data["findings"] = [finding_to_dict(f) for f in s.findings]
        data["patches"] = [
            {
                "finding_title": p.finding_title,
                "file_hint": p.file_hint,
                "diff": p.diff,
                "explanation": p.explanation,
            }
            for p in s.patches
        ]
        data["attack_chains"] = [
            {"name": c.name, "steps": c.steps or [], "impact": c.impact}
            for c in s.attack_chains
        ]
    return data


def target_to_dict(t: Target) -> dict[str, Any]:
    return {
        "id": str(t.id),
        "host": t.host,
        "display_name": t.display_name,
        "method": t.method.value if isinstance(t.method, VerificationMethod) else t.method,
        "verification_token": t.verification_token,
        "verified": t.verified,
        "verified_at": t.verified_at.isoformat() if t.verified_at else None,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


# --------------------------------------------------------------------------- #
# Organizations & users                                                       #
# --------------------------------------------------------------------------- #


def create_organization(db: Session, *, name: str, slug: str, plan: str = "free") -> Organization:
    org = Organization(name=name, slug=slug, plan=plan)
    db.add(org)
    db.flush()
    return org


def get_org_by_slug(db: Session, slug: str) -> Organization | None:
    return db.scalar(select(Organization).where(Organization.slug == slug))


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email.lower()))


def create_user(db: Session, *, org_id: uuid.UUID, email: str, password_hash: str, role: UserRole = UserRole.OWNER) -> User:
    user = User(org_id=org_id, email=email.lower(), password_hash=password_hash, role=role)
    db.add(user)
    db.flush()
    return user


# --------------------------------------------------------------------------- #
# API keys                                                                    #
# --------------------------------------------------------------------------- #


def create_api_key(db: Session, *, org_id: uuid.UUID, name: str, prefix: str, key_hash: str) -> ApiKey:
    key = ApiKey(org_id=org_id, name=name, prefix=prefix, key_hash=key_hash)
    db.add(key)
    db.flush()
    return key


def get_api_key_by_hash(db: Session, key_hash: str) -> ApiKey | None:
    return db.scalar(
        select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.revoked_at.is_(None))
    )


def touch_api_key(db: Session, key: ApiKey) -> None:
    key.last_used_at = _utcnow()


def list_api_keys(db: Session, org_id: uuid.UUID) -> Sequence[ApiKey]:
    return db.scalars(select(ApiKey).where(ApiKey.org_id == org_id).order_by(ApiKey.created_at)).all()


# --------------------------------------------------------------------------- #
# Targets                                                                     #
# --------------------------------------------------------------------------- #


def get_target(db: Session, org_id: uuid.UUID, host: str) -> Target | None:
    return db.scalar(select(Target).where(Target.org_id == org_id, Target.host == host.lower()))


def list_targets(db: Session, org_id: uuid.UUID) -> Sequence[Target]:
    return db.scalars(select(Target).where(Target.org_id == org_id).order_by(Target.created_at)).all()


def upsert_target(
    db: Session, *, org_id: uuid.UUID, host: str, display_name: str,
    method: VerificationMethod, verification_token: str,
) -> Target:
    existing = get_target(db, org_id, host)
    if existing is not None:
        existing.display_name = display_name or existing.display_name
        existing.method = method
        existing.verification_token = verification_token
        return existing
    target = Target(
        org_id=org_id, host=host.lower(), display_name=display_name,
        method=method, verification_token=verification_token,
    )
    db.add(target)
    db.flush()
    return target


def count_verified_targets(db: Session, org_id: uuid.UUID) -> int:
    return db.scalar(
        select(func.count()).select_from(Target).where(Target.org_id == org_id, Target.verified.is_(True))
    ) or 0


# --------------------------------------------------------------------------- #
# Scans (also the work queue)                                                 #
# --------------------------------------------------------------------------- #


def create_scan(db: Session, *, org_id: uuid.UUID, target_url: str, target_id: uuid.UUID | None = None) -> Scan:
    scan = Scan(org_id=org_id, target_url=target_url, target_id=target_id, status=ScanStatus.QUEUED)
    db.add(scan)
    db.flush()
    return scan


def get_scan(db: Session, scan_id: str | uuid.UUID, org_id: uuid.UUID | None = None) -> Scan | None:
    stmt = (
        select(Scan)
        .where(Scan.id == _uid(scan_id))
        .options(
            selectinload(Scan.findings),
            selectinload(Scan.patches),
            selectinload(Scan.attack_chains),
        )
    )
    if org_id is not None:
        stmt = stmt.where(Scan.org_id == org_id)
    return db.scalar(stmt)


def list_scans(db: Session, org_id: uuid.UUID, *, limit: int = 50) -> Sequence[Scan]:
    return db.scalars(
        select(Scan)
        .where(Scan.org_id == org_id)
        .options(selectinload(Scan.findings))
        .order_by(Scan.created_at.desc())
        .limit(limit)
    ).all()


def previous_completed_scan(db: Session, org_id: uuid.UUID, target_url: str, exclude_id: uuid.UUID) -> Scan | None:
    """Most recent done scan of the same target — HillClimb memory source."""
    return db.scalar(
        select(Scan)
        .where(
            Scan.org_id == org_id,
            Scan.target_url == target_url,
            Scan.status == ScanStatus.DONE,
            Scan.id != exclude_id,
        )
        .options(selectinload(Scan.findings))
        .order_by(Scan.created_at.desc())
        .limit(1)
    )


def claim_next_queued_scan(db: Session, worker_id: str) -> Scan | None:
    """Atomically claim one queued scan for this worker.

    Uses ``FOR UPDATE SKIP LOCKED`` so many workers can poll concurrently
    without ever grabbing the same row. The claimed row is flipped to
    ``running`` inside the same transaction.
    """
    scan = db.scalar(
        select(Scan)
        .where(Scan.status == ScanStatus.QUEUED)
        .order_by(Scan.created_at)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if scan is None:
        return None
    scan.status = ScanStatus.RUNNING
    scan.worker_id = worker_id
    scan.locked_at = _utcnow()
    scan.started_at = _utcnow()
    scan.attempts += 1
    db.flush()
    return scan


def finish_scan(
    db: Session, scan: Scan, *, status: ScanStatus, risk_score: int | None = None,
    regression_summary: dict | None = None, error: str = "",
    usage: dict[str, Any] | None = None,
) -> None:
    scan.status = status
    scan.risk_score = risk_score
    scan.regression_summary = regression_summary
    scan.error = error
    if usage:
        scan.tokens_used = usage.get("total_tokens")
        scan.llm_calls = usage.get("llm_calls")
        scan.cost_usd = usage.get("cost_usd")
    scan.finished_at = _utcnow()


def monthly_scan_count(db: Session, org_id: uuid.UUID) -> int:
    return db.scalar(
        select(func.count())
        .select_from(Scan)
        .where(Scan.org_id == org_id, Scan.created_at >= func.date_trunc("month", func.now()))
    ) or 0


# --------------------------------------------------------------------------- #
# Findings / patches / chains / logs                                          #
# --------------------------------------------------------------------------- #


def replace_findings(db: Session, scan_id: uuid.UUID, findings: list[dict[str, Any]]) -> None:
    """Persist the final finding set for a scan (called once at scan end)."""
    for f in findings:
        db.add(
            Finding(
                scan_id=scan_id,
                title=str(f.get("title", "")),
                category=str(f.get("category", "")),
                severity=str(f.get("severity", "info")),
                target=str(f.get("target", "")),
                description=str(f.get("description", "")),
                evidence=str(f.get("evidence", "")),
                reproduction=list(f.get("reproduction", []) or []),
                remediation=str(f.get("remediation", "")),
                confirmed=bool(f.get("confirmed", False)),
                false_positive=bool(f.get("false_positive", False)),
                discovered_by=str(f.get("discovered_by", "")),
                regression=str(f.get("regression", "new")),
            )
        )


def save_patches(db: Session, scan_id: uuid.UUID, patches: list[dict[str, Any]]) -> None:
    for p in patches:
        db.add(
            Patch(
                scan_id=scan_id,
                finding_title=str(p.get("finding_title", "")),
                file_hint=str(p.get("file_hint", "")),
                diff=str(p.get("diff", "")),
                explanation=str(p.get("explanation", "")),
            )
        )


def save_attack_chains(db: Session, scan_id: uuid.UUID, chains: list[dict[str, Any]]) -> None:
    for c in chains:
        db.add(
            AttackChain(
                scan_id=scan_id,
                name=str(c.get("name", "")),
                steps=list(c.get("steps", []) or []),
                impact=str(c.get("impact", "")),
            )
        )


def append_log(db: Session, scan_id: uuid.UUID, seq: int, line: str) -> None:
    db.add(ScanLog(scan_id=scan_id, seq=seq, line=line))


# --------------------------------------------------------------------------- #
# GitHub integrations                                                         #
# --------------------------------------------------------------------------- #


def list_github_integrations(db: Session, org_id: uuid.UUID) -> Sequence[GitHubIntegration]:
    return db.scalars(
        select(GitHubIntegration).where(GitHubIntegration.org_id == org_id).order_by(GitHubIntegration.created_at)
    ).all()


def get_github_integration(db: Session, org_id: uuid.UUID) -> GitHubIntegration | None:
    """The org's default (oldest) GitHub integration, if any."""
    return db.scalar(
        select(GitHubIntegration)
        .where(GitHubIntegration.org_id == org_id)
        .order_by(GitHubIntegration.created_at)
        .limit(1)
    )


def upsert_github_integration(
    db: Session, *, org_id: uuid.UUID, repo_full_name: str, token_encrypted: str, default_branch: str
) -> GitHubIntegration:
    existing = db.scalar(
        select(GitHubIntegration).where(
            GitHubIntegration.org_id == org_id, GitHubIntegration.repo_full_name == repo_full_name
        )
    )
    if existing is not None:
        existing.token_encrypted = token_encrypted
        existing.default_branch = default_branch
        return existing
    integ = GitHubIntegration(
        org_id=org_id, repo_full_name=repo_full_name, token_encrypted=token_encrypted, default_branch=default_branch
    )
    db.add(integ)
    db.flush()
    return integ


def delete_github_integration(db: Session, org_id: uuid.UUID, integration_id: uuid.UUID) -> bool:
    integ = db.get(GitHubIntegration, integration_id)
    if integ is None or integ.org_id != org_id:
        return False
    db.delete(integ)
    return True


def get_logs(db: Session, scan_id: uuid.UUID, *, after_seq: int = -1) -> list[ScanLog]:
    return list(
        db.scalars(
            select(ScanLog)
            .where(ScanLog.scan_id == scan_id, ScanLog.seq > after_seq)
            .order_by(ScanLog.seq)
        ).all()
    )
