-- RedHive database schema.
--
-- Auto-loaded by the Postgres container on first boot (mounted into
-- /docker-entrypoint-initdb.d/). Mirrors the shared contract in
-- redhive/models.py (Finding fields) so the API can round-trip cleanly.

-- gen_random_uuid() lives in pgcrypto.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- One row per scan / engagement.
CREATE TABLE IF NOT EXISTS scans (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target      TEXT NOT NULL,
    -- pending -> running -> done | failed
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ NULL
);

-- One row per vulnerability discovered during a scan.
-- Column set matches redhive.models.Finding.
CREATE TABLE IF NOT EXISTS findings (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id        UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    title          TEXT NOT NULL,
    category       TEXT NOT NULL,
    severity       TEXT NOT NULL DEFAULT 'info',
    target         TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    evidence       TEXT NOT NULL DEFAULT '',
    -- step-by-step reproduction, stored as a JSON array of strings
    reproduction   JSONB NOT NULL DEFAULT '[]'::jsonb,
    remediation    TEXT NOT NULL DEFAULT '',
    confirmed      BOOLEAN NOT NULL DEFAULT false,
    false_positive BOOLEAN NOT NULL DEFAULT false,
    discovered_by  TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Findings are almost always queried by their parent scan.
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
