"""Shared test fixtures.

Tests run against a dedicated ``redhive_test`` Postgres database so they never
touch dev/prod data. The env var is set *before* any ``redhive`` import so the
config picks up the test DSN. The schema is created once per session from the
ORM metadata, and every test starts from truncated tables.
"""

from __future__ import annotations

import os

os.environ.setdefault(
    "DATABASE_URL", "postgresql://redhive:redhive@localhost:5432/redhive_test"
)
os.environ.setdefault("SECRET_KEY", "test-secret-key-deterministic-000000000000")
os.environ.setdefault("LLM_PROVIDER", "openai")
os.environ.setdefault("OPENAI_API_KEY", "test-not-used")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from redhive.database import engine  # noqa: E402
from redhive.db_models import Base  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _schema() -> None:
    with engine.begin() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
    Base.metadata.drop_all(engine)
    # Drop any leftover enum types (e.g. created by a prior `alembic upgrade`)
    # so create_all can recreate them without a "type already exists" clash.
    with engine.begin() as conn:
        for enum_name in ("scan_status", "user_role", "verification_method"):
            conn.execute(text(f"DROP TYPE IF EXISTS {enum_name} CASCADE"))
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture(autouse=True)
def _clean_tables() -> None:
    """Truncate all tables before each test for isolation."""
    tables = ", ".join(t.name for t in reversed(Base.metadata.sorted_tables))
    with engine.begin() as conn:
        conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    yield


@pytest.fixture()
def client() -> TestClient:
    from redhive.api.app import app

    return TestClient(app)


@pytest.fixture()
def org_key(client: TestClient) -> str:
    """Signup a fresh org and return its API key."""
    resp = client.post(
        "/auth/signup",
        json={"org_name": "Test Org", "email": "owner@test.com", "password": "password123"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["api_key"]
