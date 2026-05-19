# Architecture

## Overview

recon-engine follows a layered architecture. Each layer has a single responsibility
and depends only on layers below it. No layer reaches upward.

```
CLI (main.py)
    │
    ▼
Engine (core/engine.py)
    │
    ├── Validator (core/validator.py)
    ├── Scanners (scanners/)
    │       ├── subdomain.py
    │       ├── ports.py
    │       └── http_fingerprint.py
    ├── Store (database/store.py)
    └── Models (models/)
            ├── target.py
            └── results.py

Reports (reports/)
Export  (utils/exporter.py)
```

## Layer Descriptions

### CLI (`main.py`)
Entry point. Parses user flags, delegates to the engine, and renders Rich tables.
Contains no business logic. All validation errors are surfaced here as user-readable messages.

### Engine (`core/engine.py`)
Orchestrates scanner modules in sequence. Writes results to the store after
each phase. If any scanner fails, partial results are preserved.

### Validator (`core/validator.py`)
Parses raw user input into a typed `Target` object. All scanners receive a `Target`;
they never receive raw strings. This is the single point where input is sanitised.

### Scanners (`scanners/`)
Three independent modules. Each accepts a `Target` and returns typed result objects.
Scanners are async-first and communicate only through return values — no shared state.

- **subdomain.py**: Queries crt.sh certificate transparency logs. Optionally resolves
  discovered subdomains via DNS.
- **ports.py**: Async TCP connect scanner. Uses `asyncio.open_connection` with a
  concurrency semaphore. No raw sockets, no root privileges required.
- **http_fingerprint.py**: Issues HTTP GET requests via aiohttp. Extracts server headers
  and infers technologies through a rule table.

### Models (`models/`)
Pydantic v2 models with field-level validation. No business logic. Used by all layers.

- **target.py**: `Target`, `TargetType`
- **results.py**: `SubdomainResult`, `PortResult`, `HTTPFingerprint`, `ScanSession`

### Database (`database/`)
- **schema.py**: DDL strings applied on first connection.
- **store.py**: Thin sqlite3 wrapper. All queries use parameterised statements.
  JSON columns (technologies, headers) are serialised with `json.dumps`.

### Reports (`reports/`)
Stateless renderer that accepts a `ScanSession` and writes a Markdown file.
Does not touch the database.

### Export (`utils/exporter.py`)
Serialises a `ScanSession` to JSON. Does not touch the database.

## Data Flow

```
User input (raw string)
    │
    ▼
parse_target() → Target
    │
    ▼
ReconEngine.run_full_scan()
    │
    ├── enumerate_subdomains(target) → List[SubdomainResult]
    │       └── store.save_subdomains()
    ├── scan_ports(target) → List[PortResult]
    │       └── store.save_ports()
    └── fingerprint_http(target) → List[HTTPFingerprint]
            └── store.save_fingerprints()
    │
    ▼
ScanSession (in-memory, also persisted)
    │
    ├── export_session_json(session) → .json file
    └── generate_markdown_report(session) → .md file
```

## Design Decisions

**Why sync store + async engine?**
sqlite3 does not support async natively. The store operations are fast (sub-millisecond
for typical scan sizes) and are called sequentially between scanner phases, so there is
no benefit to async I/O for the database layer.

**Why no subprocess?**
Shell subprocesses introduce injection risk and environment dependency. All scanning
is performed through Python libraries or direct asyncio socket operations.

**Why Pydantic for models?**
Validation at the model boundary is cheaper than defensive checks scattered across
every function. A single bad value fails fast with a clear error rather than
propagating silently.

**Why no plugin system?**
The MVP solves a clear, bounded problem. A plugin interface adds abstraction cost
without current benefit. Extending scanners is done by adding a module under
`scanners/` and wiring it in `engine.py`.
