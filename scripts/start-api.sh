#!/usr/bin/env bash
# API container entrypoint: apply DB migrations, then serve.
# Running migrations here (idempotent) means a fresh deploy self-bootstraps its
# schema; re-deploys are no-ops once at head.
set -euo pipefail

echo "[start-api] running database migrations..."
alembic upgrade head

echo "[start-api] launching uvicorn..."
exec uvicorn redhive.api.app:app --host 0.0.0.0 --port 8000
