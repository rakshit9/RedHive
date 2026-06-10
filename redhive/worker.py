"""Scan worker — the background process that actually runs engagements.

Run one or many of these alongside the API::

    python -m redhive.worker

Each worker loops: claim the oldest ``queued`` scan via ``FOR UPDATE SKIP
LOCKED`` (so N workers never collide), run the multi-agent engagement,
persisting every log line and the final results to Postgres. The API's SSE
endpoint tails the persisted ``scan_logs`` rows, so streaming works across
processes without any shared in-memory state.

Crash-safety: a scan is flipped to ``running`` the moment it's claimed; if the
worker dies mid-scan the row stays ``running`` and a reaper (``_requeue_stale``)
returns long-stuck scans to the queue on the next poll.
"""

from __future__ import annotations

import os
import signal
import socket
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import update

from redhive import repository as repo
from redhive.agents.graph import run_engagement
from redhive.database import session_scope
from redhive.db_models import Scan, ScanStatus
from redhive.memory import diff_findings
from redhive.scope import ScopeError, authorize_host, is_allowed

POLL_INTERVAL_SECONDS = 2.0
# A scan still 'running' after this long is presumed dead and requeued.
STALE_AFTER = timedelta(minutes=30)

_shutdown = False


def _worker_id() -> str:
    return f"{socket.gethostname()}-{os.getpid()}"


def _handle_signal(signum, _frame) -> None:  # noqa: ANN001
    global _shutdown
    _shutdown = True
    print(f"[worker] received signal {signum}; finishing current scan then exiting.")


def _requeue_stale() -> None:
    """Return scans stuck in 'running' past the deadline to the queue."""
    cutoff = datetime.now(timezone.utc) - STALE_AFTER
    with session_scope() as db:
        db.execute(
            update(Scan)
            .where(Scan.status == ScanStatus.RUNNING, Scan.locked_at < cutoff)
            .values(status=ScanStatus.QUEUED, worker_id="", locked_at=None)
        )


def _run_one(scan_id, org_id, target_url) -> None:  # noqa: ANN001
    """Execute a single claimed scan and persist all results.

    Runs in its own session lifecycle so a failure here never poisons the
    claim loop. Log lines are committed one at a time so the SSE tail sees
    progress in near real time.
    """
    seq = {"n": 0}

    def emit(line: str) -> None:
        with session_scope() as db:
            repo.append_log(db, scan_id, seq["n"], line)
        seq["n"] += 1

    try:
        # The host was ownership-verified by the API before enqueue; re-authorize
        # it in THIS process so the tool-level scope chokepoint accepts it.
        if not is_allowed(target_url):
            authorize_host(target_url)

        emit(f"[worker] {_worker_id()} picked up scan {scan_id}.")
        state = run_engagement(target_url, log_callback=emit)
        findings = state.get("confirmed") or state.get("findings") or []

        # HillClimb memory: diff against this org+target's previous done scan.
        with session_scope() as db:
            prev = repo.previous_completed_scan(db, org_id, target_url, scan_id)
            previous = [repo.finding_to_dict(f) for f in prev.findings] if prev else []
        annotated, _fixed, summary = diff_findings(previous, list(findings))

        usage = state.get("usage") or {}
        with session_scope() as db:
            scan = repo.get_scan(db, scan_id)
            repo.replace_findings(db, scan_id, annotated)
            repo.save_patches(db, scan_id, state.get("patches", []))
            repo.save_attack_chains(db, scan_id, state.get("attack_chains", []))
            repo.finish_scan(
                db, scan, status=ScanStatus.DONE,
                risk_score=state.get("risk_score"),
                regression_summary=summary,
                usage=usage,
            )
        if usage:
            emit(
                f"[usage] {usage.get('total_tokens', 0):,} tokens across "
                f"{usage.get('llm_calls', 0)} LLM call(s) — est. ${usage.get('cost_usd', 0):.4f}."
            )
        if previous:
            emit(
                f"[memory] vs previous scan — {summary['new']} new, "
                f"{summary['recurring']} recurring, {summary['fixed']} fixed."
            )
        emit(f"[worker] scan {scan_id} complete.")
    except ScopeError as exc:
        _fail(scan_id, f"scope refused: {exc}")
    except Exception as exc:  # noqa: BLE001 — one bad scan must not kill the worker
        _fail(scan_id, f"scan failed: {exc}")


def _fail(scan_id, message: str) -> None:  # noqa: ANN001
    with session_scope() as db:
        repo.append_log(db, scan_id, 10_000_000, f"[error] {message}")
        scan = repo.get_scan(db, scan_id)
        if scan is not None:
            repo.finish_scan(db, scan, status=ScanStatus.FAILED, error=message)


def run_forever() -> None:
    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)
    wid = _worker_id()
    print(f"[worker] {wid} online; polling for queued scans.")

    last_reap = 0.0
    while not _shutdown:
        # Periodically reap stale 'running' scans (every ~minute).
        now = time.monotonic()
        if now - last_reap > 60:
            try:
                _requeue_stale()
            except Exception as exc:  # noqa: BLE001
                print(f"[worker] reaper error: {exc}")
            last_reap = now

        claimed = None
        try:
            with session_scope() as db:
                scan = repo.claim_next_queued_scan(db, wid)
                if scan is not None:
                    claimed = (scan.id, scan.org_id, scan.target_url)
        except Exception as exc:  # noqa: BLE001 — DB blip; back off and retry
            print(f"[worker] claim error: {exc}")
            time.sleep(POLL_INTERVAL_SECONDS)
            continue

        if claimed is None:
            time.sleep(POLL_INTERVAL_SECONDS)
            continue

        _run_one(*claimed)

    print(f"[worker] {wid} shut down cleanly.")


if __name__ == "__main__":
    run_forever()
