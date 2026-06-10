"""SQLAlchemy ORM models — the product's persistent data model.

Multi-tenant from the ground up: every customer-owned row hangs off an
``Organization``. The object graph::

    Organization 1──* User
                 1──* ApiKey
                 1──* Target
                 1──* Scan ──* Finding
                            ──* Patch
                            ──* AttackChain
                            ──* ScanLog

The ``Scan`` table doubles as the work queue: a row created with
``status="queued"`` is claimed by a worker via ``SELECT ... FOR UPDATE SKIP
LOCKED`` (see ``redhive.worker``). All timestamps are timezone-aware UTC.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _enum(py_enum: type[enum.Enum], name: str) -> SAEnum:
    """A Postgres enum column that stores the member *value* (e.g. "owner"),
    not its NAME (SQLAlchemy's surprising default). ``create_type=False`` because
    the type is created by the Alembic migration, not on table autocreate."""
    return SAEnum(
        py_enum,
        name=name,
        values_callable=lambda e: [m.value for m in e],
        create_type=False,
    )


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------- #
# Enums                                                                       #
# --------------------------------------------------------------------------- #


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELED = "canceled"


class UserRole(str, enum.Enum):
    OWNER = "owner"
    MEMBER = "member"


class VerificationMethod(str, enum.Enum):
    DNS_TXT = "dns_txt"
    HTTP_FILE = "http_file"
    PRACTICE = "practice"  # built-in practice targets (juiceshop/localhost)


# --------------------------------------------------------------------------- #
# Tenancy: orgs, users, API keys                                              #
# --------------------------------------------------------------------------- #


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    # Billing plan: free | pro | enterprise. Drives scan/target quotas.
    plan: Mapped[str] = mapped_column(String(40), nullable=False, default="free")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    users: Mapped[list["User"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    targets: Mapped[list["Target"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    scans: Mapped[list["Scan"]] = relationship(back_populates="organization", cascade="all, delete-orphan")
    github_integrations: Mapped[list["GitHubIntegration"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(_enum(UserRole, "user_role"), default=UserRole.OWNER)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    organization: Mapped[Organization] = relationship(back_populates="users")


class ApiKey(Base):
    """A programmatic-access key.

    The plaintext key is shown exactly once at creation (``rh_<prefix>_<secret>``).
    We persist only a one-way hash of the full key plus the visible ``prefix`` so
    users can identify a key in the UI without us ever storing the secret.
    """

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False, default="default")
    prefix: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    organization: Mapped[Organization] = relationship(back_populates="api_keys")


# --------------------------------------------------------------------------- #
# Targets (ownership-verified scan scope)                                     #
# --------------------------------------------------------------------------- #


class Target(Base):
    """A host an organization is authorized to scan.

    A target is only scannable once ``verified`` is true (the org proved
    ownership via DNS TXT or an HTTP file), except built-in ``PRACTICE`` targets
    which are pre-verified.
    """

    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("org_id", "host", name="uq_target_org_host"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    method: Mapped[VerificationMethod] = mapped_column(
        _enum(VerificationMethod, "verification_method"), default=VerificationMethod.DNS_TXT
    )
    verification_token: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    organization: Mapped[Organization] = relationship(back_populates="targets")


# --------------------------------------------------------------------------- #
# Scans + results                                                             #
# --------------------------------------------------------------------------- #


class Scan(Base):
    """One engagement. Doubles as the work-queue row (status=queued -> claimed)."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True
    )
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        _enum(ScanStatus, "scan_status"), default=ScanStatus.QUEUED, index=True
    )
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    regression_summary: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # LLM usage for this scan (filled in when the engagement finishes).
    tokens_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    llm_calls: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Work-queue bookkeeping for FOR UPDATE SKIP LOCKED claiming.
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    worker_id: Mapped[str] = mapped_column(String(80), nullable=False, default="")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization: Mapped[Organization] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="Finding.created_at"
    )
    patches: Mapped[list["Patch"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    attack_chains: Mapped[list["AttackChain"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    logs: Mapped[list["ScanLog"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="ScanLog.seq"
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    target: Mapped[str] = mapped_column(Text, nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")
    reproduction: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    remediation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    false_positive: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    discovered_by: Mapped[str] = mapped_column(String(80), nullable=False, default="")
    # HillClimb regression bucket vs the target's previous scan: new|recurring.
    regression: Mapped[str] = mapped_column(String(20), nullable=False, default="new")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class Patch(Base):
    __tablename__ = "patches"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_title: Mapped[str] = mapped_column(Text, nullable=False, default="")
    file_hint: Mapped[str] = mapped_column(Text, nullable=False, default="")
    diff: Mapped[str] = mapped_column(Text, nullable=False, default="")
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped[Scan] = relationship(back_populates="patches")


class AttackChain(Base):
    __tablename__ = "attack_chains"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(Text, nullable=False, default="")
    steps: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    impact: Mapped[str] = mapped_column(Text, nullable=False, default="")

    scan: Mapped[Scan] = relationship(back_populates="attack_chains")


class GitHubIntegration(Base):
    """A connected GitHub repository RedHive can open remediation PRs against.

    The access token is stored encrypted (see ``redhive.crypto``); we never
    persist it in plaintext. One row per (org, repo).
    """

    __tablename__ = "github_integrations"
    __table_args__ = (UniqueConstraint("org_id", "repo_full_name", name="uq_github_org_repo"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    repo_full_name: Mapped[str] = mapped_column(String(255), nullable=False)  # "owner/repo"
    token_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    default_branch: Mapped[str] = mapped_column(String(120), nullable=False, default="main")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    organization: Mapped[Organization] = relationship(back_populates="github_integrations")


class ScanLog(Base):
    """One log line. Persisted so the SSE endpoint can replay a scan's full log
    after an API restart and so logs survive for audit/compliance."""

    __tablename__ = "scan_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    line: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped[Scan] = relationship(back_populates="logs")
