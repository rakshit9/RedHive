"""RedHive HTTP API — the multi-tenant web layer.

Thin assembly layer: it wires CORS, mounts the feature routers, and exposes a
health probe. All real logic lives in the routers and the repository/worker.

Routers
-------
- ``routes_auth``    signup / login / profile / API-key management
- ``routes_targets`` register a host, prove ownership, list targets
- ``routes_scans``   enqueue scans, read results, stream the live log (SSE)

Scans are *enqueued* here and executed by a separate worker process
(``python -m redhive.worker``), so the API never blocks on a scan and the
system scales by adding workers.
"""

from __future__ import annotations

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from redhive.api.routes_auth import router as auth_router
from redhive.api.routes_scans import router as scans_router
from redhive.api.routes_targets import router as targets_router
from redhive.config import settings

app = FastAPI(
    title="RedHive",
    summary="Autonomous multi-agent pentest platform.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(targets_router)
app.include_router(scans_router)


@app.get("/healthz", tags=["meta"])
async def healthz() -> dict:
    """Liveness probe."""
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("redhive.api.app:app", host="0.0.0.0", port=8000, reload=True)
