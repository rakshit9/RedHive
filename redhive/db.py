"""Persistence layer for scans and findings.

Thin SQLAlchemy 2.0 (core) wrapper over the schema in db/schema.sql. The rest
of the system talks to Postgres only through these helpers so the SQL lives in
one place. Uses `settings.database_url`.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from redhive.config import settings


class DatabaseError(RuntimeError):
    """Raised when a database operation fails (connection, query, etc.)."""


# Single shared engine. `pool_pre_ping` quietly recycles dead connections so a
# restarted Postgres container does not poison the pool.
_engine: Engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)


def _row_to_dict(row: Any) -> dict[str, Any]:
    """Convert a SQLAlchemy Row into a plain dict (with str ids/timestamps)."""
    data: dict[str, Any] = dict(row._mapping)
    for key, value in data.items():
        # UUIDs and datetimes are not JSON-serializable as-is; stringify them.
        if key in ("id", "scan_id") and value is not None:
            data[key] = str(value)
        elif key in ("created_at", "finished_at") and value is not None:
            data[key] = value.isoformat()
    return data


def create_scan(target: str) -> str:
    """Insert a new pending scan and return its id as a string."""
    try:
        with _engine.begin() as conn:
            result = conn.execute(
                text(
                    "INSERT INTO scans (target, status) "
                    "VALUES (:target, 'pending') RETURNING id"
                ),
                {"target": target},
            )
            return str(result.scalar_one())
    except SQLAlchemyError as exc:
        raise DatabaseError(f"Failed to create scan for {target!r}: {exc}") from exc


def set_scan_status(scan_id: str, status: str) -> None:
    """Update a scan's status; stamps finished_at for terminal states."""
    # done/failed are terminal -> record when the scan wrapped up.
    finished = "now()" if status in ("done", "failed") else "finished_at"
    try:
        with _engine.begin() as conn:
            conn.execute(
                text(
                    f"UPDATE scans SET status = :status, finished_at = {finished} "
                    "WHERE id = :scan_id"
                ),
                {"status": status, "scan_id": scan_id},
            )
    except SQLAlchemyError as exc:
        raise DatabaseError(
            f"Failed to set status {status!r} on scan {scan_id}: {exc}"
        ) from exc


def save_finding(scan_id: str, finding: dict[str, Any]) -> str:
    """Persist a single finding (a serialized redhive.models.Finding).

    Missing keys fall back to schema-friendly defaults, so a partially
    populated finding dict is still safe to store.
    """
    params = {
        "scan_id": scan_id,
        "title": finding.get("title", ""),
        "category": finding.get("category", ""),
        "severity": finding.get("severity", "info"),
        "target": finding.get("target", ""),
        "description": finding.get("description", ""),
        "evidence": finding.get("evidence", ""),
        # reproduction is a list[str] -> store as JSON for the jsonb column.
        "reproduction": json.dumps(finding.get("reproduction", [])),
        "remediation": finding.get("remediation", ""),
        "confirmed": bool(finding.get("confirmed", False)),
        "false_positive": bool(finding.get("false_positive", False)),
        "discovered_by": finding.get("discovered_by", ""),
    }
    try:
        with _engine.begin() as conn:
            result = conn.execute(
                text(
                    "INSERT INTO findings (scan_id, title, category, severity, "
                    "target, description, evidence, reproduction, remediation, "
                    "confirmed, false_positive, discovered_by) VALUES "
                    "(:scan_id, :title, :category, :severity, :target, "
                    ":description, :evidence, CAST(:reproduction AS jsonb), "
                    ":remediation, :confirmed, :false_positive, :discovered_by) "
                    "RETURNING id"
                ),
                params,
            )
            return str(result.scalar_one())
    except SQLAlchemyError as exc:
        raise DatabaseError(
            f"Failed to save finding for scan {scan_id}: {exc}"
        ) from exc


def get_scan(scan_id: str) -> dict[str, Any]:
    """Fetch a single scan by id. Raises DatabaseError if not found."""
    try:
        with _engine.connect() as conn:
            row = conn.execute(
                text("SELECT * FROM scans WHERE id = :scan_id"),
                {"scan_id": scan_id},
            ).fetchone()
    except SQLAlchemyError as exc:
        raise DatabaseError(f"Failed to fetch scan {scan_id}: {exc}") from exc

    if row is None:
        raise DatabaseError(f"Scan {scan_id} not found")
    return _row_to_dict(row)


def get_findings(scan_id: str) -> list[dict[str, Any]]:
    """Return all findings for a scan, oldest first."""
    try:
        with _engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT * FROM findings WHERE scan_id = :scan_id "
                    "ORDER BY created_at ASC"
                ),
                {"scan_id": scan_id},
            ).fetchall()
    except SQLAlchemyError as exc:
        raise DatabaseError(
            f"Failed to fetch findings for scan {scan_id}: {exc}"
        ) from exc

    return [_row_to_dict(row) for row in rows]
