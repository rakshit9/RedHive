"""HTTP API for RedHive — the thin web layer over the multi-agent engine.

Exposes scan lifecycle endpoints used by the (future) Next.js UI and by curl
during demos:

    POST /scans                start an authorized scan (background task)
    GET  /scans/{scan_id}      status + findings + accumulated log
    GET  /scans/{scan_id}/log  live log as Server-Sent Events
    GET  /healthz              liveness probe

Design notes
------------
- An in-memory ``_SCANS`` dict is the single source of truth for streaming and
  the fallback store. Postgres is best-effort: every DB call is wrapped so the
  demo keeps running if the database is down (``DatabaseError`` is swallowed).
- ``run_engagement`` is synchronous and CPU/IO heavy, so it runs in a worker
  thread. Its ``log_callback`` pushes lines onto a per-scan ``asyncio.Queue``
  that the SSE endpoint drains, plus mirrors them into ``_SCANS`` for late
  subscribers and the plain GET endpoint.
"""

from __future__ import annotations

import asyncio
import threading
import time
import uuid
from typing import Any

import uvicorn
from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from redhive import db, report
from redhive.agents.graph import run_engagement
from redhive.memory import diff_findings
from redhive.scope import ScopeError, assert_allowed

app = FastAPI(
    title="RedHive",
    summary="Autonomous multi-agent pentest platform.",
    version="0.1.0",
)

# Permissive CORS so a local Next.js dev server (any port) can call the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# In-memory state                                                             #
# --------------------------------------------------------------------------- #

# scan_id -> {"target", "status", "findings": list[dict], "log": list[str]}
_SCANS: dict[str, dict[str, Any]] = {}

# scan_id -> asyncio.Queue used to fan log lines out to the SSE endpoint. A
# sentinel ``None`` is enqueued when the scan finishes so the stream can close.
_LOG_QUEUES: dict[str, asyncio.Queue[str | None]] = {}

_DONE = object()  # marker placed in a queue (as the sentinel) when a scan ends


class ScanRequest(BaseModel):
    target: str


def _previous_findings(target: str, current_scan_id: str) -> list[dict[str, Any]]:
    """Most recent completed scan's findings for ``target`` (HillClimb memory).

    Searches the in-memory store (newest first), then falls back to Postgres.
    Returns ``[]`` when this is the target's first scan.
    """
    candidates = [
        (sid, rec)
        for sid, rec in _SCANS.items()
        if sid != current_scan_id
        and rec.get("target") == target
        and rec.get("status") == "done"
    ]
    candidates.sort(key=lambda kv: kv[1].get("created_at", 0), reverse=True)
    if candidates:
        return candidates[0][1].get("findings", [])
    return []


# --------------------------------------------------------------------------- #
# DB helpers (best-effort — never raise out)                                  #
# --------------------------------------------------------------------------- #

def _db_create_scan(target: str) -> str | None:
    """Try to persist a new scan. Return its DB id, or None if DB is down."""
    try:
        return db.create_scan(target)
    except db.DatabaseError:
        return None


def _db_set_status(scan_id: str, status: str) -> None:
    try:
        db.set_scan_status(scan_id, status)
    except db.DatabaseError:
        pass


def _db_save_finding(scan_id: str, finding: dict[str, Any]) -> None:
    try:
        db.save_finding(scan_id, finding)
    except db.DatabaseError:
        pass


# --------------------------------------------------------------------------- #
# Scan runner                                                                 #
# --------------------------------------------------------------------------- #

def _run_scan(scan_id: str, target: str, loop: asyncio.AbstractEventLoop) -> None:
    """Execute the engagement in a worker thread and stream its log lines.

    Runs on a background thread, so it pushes onto the per-scan asyncio.Queue
    via ``loop.call_soon_threadsafe`` (queues are not thread-safe). Mirrors
    everything into ``_SCANS`` and best-effort into Postgres.
    """
    record = _SCANS[scan_id]
    record["status"] = "running"
    _db_set_status(scan_id, "running")

    def _emit(line: str) -> None:
        record["log"].append(line)
        queue = _LOG_QUEUES.get(scan_id)
        if queue is not None:
            loop.call_soon_threadsafe(queue.put_nowait, line)

    try:
        state = run_engagement(target, log_callback=_emit)
        # Validator/reporter rewrite findings wholesale; prefer confirmed.
        findings = state.get("confirmed") or state.get("findings") or []

        # HillClimb memory: diff against this target's previous scan.
        previous = _previous_findings(target, scan_id)
        annotated, fixed, summary = diff_findings(previous, list(findings))
        record["findings"] = annotated
        record["fixed"] = fixed
        record["regression_summary"] = summary
        # Post-engagement intelligence from the strategist/patch nodes.
        record["patches"] = state.get("patches", [])
        record["attack_chains"] = state.get("attack_chains", [])
        record["risk_score"] = state.get("risk_score")
        if previous:
            _emit(
                f"[memory] vs previous scan — {summary['new']} new, "
                f"{summary['recurring']} recurring, {summary['fixed']} fixed."
            )

        for finding in annotated:
            _db_save_finding(scan_id, finding)
        record["status"] = "done"
        _db_set_status(scan_id, "done")
    except Exception as exc:  # noqa: BLE001 — surface failure, keep server alive
        record["status"] = "failed"
        record["log"].append(f"[error] scan failed: {exc}")
        _db_set_status(scan_id, "failed")
        queue = _LOG_QUEUES.get(scan_id)
        if queue is not None:
            loop.call_soon_threadsafe(
                queue.put_nowait, f"[error] scan failed: {exc}"
            )
    finally:
        # Signal the SSE stream to close.
        queue = _LOG_QUEUES.get(scan_id)
        if queue is not None:
            loop.call_soon_threadsafe(queue.put_nowait, None)


# --------------------------------------------------------------------------- #
# Endpoints                                                                   #
# --------------------------------------------------------------------------- #

@app.post("/scans")
async def create_scan(req: ScanRequest, background_tasks: BackgroundTasks) -> dict:
    """Validate scope, register the scan, and kick it off in the background."""
    try:
        assert_allowed(req.target)
    except ScopeError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    # Use the DB id when available so API ids match persisted rows; otherwise
    # mint a local uuid so the demo still works without Postgres.
    scan_id = _db_create_scan(req.target) or str(uuid.uuid4())

    _SCANS[scan_id] = {
        "target": req.target,
        "status": "running",
        "findings": [],
        "log": [],
        "fixed": [],
        "regression_summary": None,
        "risk_score": None,
        "attack_chains": [],
        "patches": [],
        "created_at": time.time(),
    }
    _LOG_QUEUES[scan_id] = asyncio.Queue()

    loop = asyncio.get_running_loop()
    # run_engagement is blocking; run it off the event loop in a thread.
    background_tasks.add_task(
        lambda: threading.Thread(
            target=_run_scan, args=(scan_id, req.target, loop), daemon=True
        ).start()
    )

    return {"scan_id": scan_id, "status": "running"}


@app.get("/scans")
async def list_scans() -> dict:
    """List scans (newest first) with a severity-count summary each."""
    items = []
    for sid, rec in sorted(
        _SCANS.items(), key=lambda kv: kv[1].get("created_at", 0), reverse=True
    ):
        counts: dict[str, int] = {}
        for f in rec.get("findings", []):
            sev = str(f.get("severity", "info"))
            counts[sev] = counts.get(sev, 0) + 1
        items.append(
            {
                "scan_id": sid,
                "target": rec.get("target"),
                "status": rec.get("status"),
                "findings": sum(counts.values()),
                "severity_counts": counts,
                "risk_score": rec.get("risk_score"),
                "regression_summary": rec.get("regression_summary"),
            }
        )
    return {"scans": items}


@app.get("/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    """Return current status, findings, regression info, and log for a scan."""
    record = _SCANS.get(scan_id)
    if record is not None:
        return {
            "scan_id": scan_id,
            "target": record["target"],
            "status": record["status"],
            "findings": record["findings"],
            "fixed": record.get("fixed", []),
            "regression_summary": record.get("regression_summary"),
            "risk_score": record.get("risk_score"),
            "attack_chains": record.get("attack_chains", []),
            "patches": record.get("patches", []),
            "log": record["log"],
        }

    # Not in memory (e.g. server restarted) — try the database.
    try:
        scan = db.get_scan(scan_id)
        findings = db.get_findings(scan_id)
    except db.DatabaseError as exc:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found") from exc

    return {
        "scan_id": scan_id,
        "target": scan.get("target", ""),
        "status": scan.get("status", "unknown"),
        "findings": findings,
        "log": [],
    }


@app.get("/scans/{scan_id}/report")
async def get_report(scan_id: str, format: str = "markdown"):
    """Export a finished scan as a Markdown (default) or JSON pentest report."""
    record = _SCANS.get(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    scan = {
        "scan_id": scan_id,
        "target": record.get("target"),
        "status": record.get("status"),
        "findings": record.get("findings", []),
        "fixed": record.get("fixed", []),
        "regression_summary": record.get("regression_summary"),
        "risk_score": record.get("risk_score"),
        "attack_chains": record.get("attack_chains", []),
        "patches": record.get("patches", []),
    }
    if format == "json":
        return report.render_json(scan)
    return PlainTextResponse(
        report.render_markdown(scan), media_type="text/markdown"
    )


@app.get("/scans/{scan_id}/log")
async def stream_log(scan_id: str) -> EventSourceResponse:
    """Stream live log lines as Server-Sent Events, then close when done."""
    if scan_id not in _SCANS:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    queue = _LOG_QUEUES.get(scan_id)

    async def event_generator():
        # Replay anything already logged so late subscribers see the full run.
        replayed = 0
        for line in list(_SCANS[scan_id]["log"]):
            yield {"event": "log", "data": line}
            replayed += 1

        # If the scan already finished, there is no live queue to drain.
        if queue is None or _SCANS[scan_id]["status"] in ("done", "failed"):
            yield {"event": "done", "data": _SCANS[scan_id]["status"]}
            return

        # The queue holds every emitted line from the start of the scan, so the
        # first ``replayed`` items are the ones we just replayed — skip them to
        # avoid sending duplicates, then stream the rest live.
        skipped = 0
        while True:
            line = await queue.get()
            if line is None:  # sentinel -> scan finished
                break
            if skipped < replayed:
                skipped += 1
                continue
            yield {"event": "log", "data": line}

        yield {"event": "done", "data": _SCANS[scan_id]["status"]}

    return EventSourceResponse(event_generator())


@app.get("/healthz")
async def healthz() -> dict:
    """Liveness probe."""
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("redhive.api.app:app", host="0.0.0.0", port=8000, reload=True)
