"""
SQLite schema DDL.

All schema changes should be made here. Forward migrations
are applied automatically on first connection (see store.py).
"""

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS scan_sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT    NOT NULL,
    started_at  TEXT    NOT NULL,
    finished_at TEXT,
    notes       TEXT
);

CREATE TABLE IF NOT EXISTS subdomains (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   INTEGER NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    subdomain    TEXT    NOT NULL,
    source       TEXT    NOT NULL,
    resolved     INTEGER NOT NULL DEFAULT 0,
    ip_address   TEXT,
    discovered_at TEXT   NOT NULL
);

CREATE TABLE IF NOT EXISTS port_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  INTEGER NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    protocol    TEXT    NOT NULL DEFAULT 'tcp',
    state       TEXT    NOT NULL,
    service     TEXT,
    banner      TEXT,
    scanned_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS http_fingerprints (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id       INTEGER NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    url              TEXT    NOT NULL,
    status_code      INTEGER,
    server           TEXT,
    content_type     TEXT,
    x_powered_by     TEXT,
    technologies     TEXT,
    headers          TEXT,
    redirect_url     TEXT,
    response_time_ms REAL,
    fingerprinted_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_subdomains_session
    ON subdomains(session_id);

CREATE INDEX IF NOT EXISTS idx_ports_session
    ON port_results(session_id);

CREATE INDEX IF NOT EXISTS idx_fingerprints_session
    ON http_fingerprints(session_id);

CREATE INDEX IF NOT EXISTS idx_sessions_target
    ON scan_sessions(target);
"""
