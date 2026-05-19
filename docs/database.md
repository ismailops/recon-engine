# Database

recon-engine uses SQLite via the standard library `sqlite3` module.
The database file is stored at `outputs/recon.db` by default.

WAL mode is enabled for better read concurrency. Foreign keys are enforced.

## Tables

### `scan_sessions`

Top-level record for each scan invocation.

| Column | Type | Description |
|---|---|---|
| id | INTEGER PK | Auto-increment session identifier |
| target | TEXT | Normalised hostname or IP |
| started_at | TEXT | ISO 8601 UTC timestamp |
| finished_at | TEXT | ISO 8601 UTC timestamp, NULL if interrupted |
| notes | TEXT | Optional operator note |

### `subdomains`

One row per discovered subdomain, per session.

| Column | Type | Description |
|---|---|---|
| id | INTEGER PK | |
| session_id | INTEGER FK | References scan_sessions(id) |
| subdomain | TEXT | Fully-qualified subdomain name |
| source | TEXT | Discovery source, e.g. "crt.sh" |
| resolved | INTEGER | 1 if DNS resolved, 0 otherwise |
| ip_address | TEXT | Resolved IPv4/v6 address, nullable |
| discovered_at | TEXT | ISO 8601 UTC timestamp |

### `port_results`

One row per probed port, per session. Closed and filtered ports are stored
to provide a complete picture of the scan.

| Column | Type | Description |
|---|---|---|
| id | INTEGER PK | |
| session_id | INTEGER FK | References scan_sessions(id) |
| port | INTEGER | TCP port number (1–65535) |
| protocol | TEXT | Always "tcp" in current version |
| state | TEXT | "open", "closed", or "filtered" |
| service | TEXT | Well-known service name, nullable |
| banner | TEXT | First 200 characters of response, nullable |
| scanned_at | TEXT | ISO 8601 UTC timestamp |

### `http_fingerprints`

One row per probed HTTP/HTTPS endpoint, per session.

| Column | Type | Description |
|---|---|---|
| id | INTEGER PK | |
| session_id | INTEGER FK | References scan_sessions(id) |
| url | TEXT | Full URL probed |
| status_code | INTEGER | HTTP response status, nullable |
| server | TEXT | Value of Server header, nullable |
| content_type | TEXT | Value of Content-Type header, nullable |
| x_powered_by | TEXT | Value of X-Powered-By header, nullable |
| technologies | TEXT | JSON array of inferred technology names |
| headers | TEXT | JSON object of sanitised response headers |
| redirect_url | TEXT | Final URL after redirect chain, nullable |
| response_time_ms | REAL | Elapsed time in milliseconds, nullable |
| fingerprinted_at | TEXT | ISO 8601 UTC timestamp |

## Indexes

| Index | Table | Column | Purpose |
|---|---|---|---|
| idx_subdomains_session | subdomains | session_id | Join performance |
| idx_ports_session | port_results | session_id | Join performance |
| idx_fingerprints_session | http_fingerprints | session_id | Join performance |
| idx_sessions_target | scan_sessions | target | Target lookup |

## Notes

- All foreign keys use `ON DELETE CASCADE`. Deleting a session removes all child rows.
- JSON columns (`technologies`, `headers`) are stored as TEXT and parsed by the application layer.
- All timestamps are stored in ISO 8601 format with UTC timezone.
- The schema is applied idempotently via `CREATE TABLE IF NOT EXISTS` on every startup.
