# recon-engine

A professional reconnaissance toolkit for authorized security assessments.
Performs passive subdomain enumeration, async TCP port scanning, HTTP
fingerprinting, result storage, and structured reporting from a single CLI.

---

## Features

- Passive subdomain enumeration via crt.sh certificate transparency logs
- Async TCP port scanning with configurable concurrency and timeout
- HTTP/HTTPS fingerprinting: status codes, server headers, technology inference
- SQLite-backed result storage with full session history
- JSON export and Markdown report generation
- Clean CLI with Rich terminal output
- Input validation and shell-injection prevention at every boundary
- No root privileges required

---

## Architecture

```
recon-engine/
├── core/
│   ├── engine.py          # Orchestrates scanner modules
│   └── validator.py       # Parses and validates all user input
├── scanners/
│   ├── subdomain.py       # crt.sh passive enumeration + DNS resolution
│   ├── ports.py           # Async TCP connect scanner
│   └── http_fingerprint.py# Header analysis and technology detection
├── database/
│   ├── schema.py          # DDL
│   └── store.py           # SQLite CRUD layer
├── models/
│   ├── target.py          # Validated Target model
│   └── results.py         # SubdomainResult, PortResult, HTTPFingerprint, ScanSession
├── reports/
│   └── markdown_report.py # Markdown report renderer
├── utils/
│   ├── exporter.py        # JSON export
│   └── logging_config.py  # Logging setup
├── tests/                 # pytest test suite
├── docs/                  # Architecture, database, and usage documentation
└── main.py                # CLI entry point (Typer)
```

See [docs/architecture.md](docs/architecture.md) for a full description of each layer
and the data flow diagram.

---

## Installation

Requires Python 3.11 or later.

```bash
git clone https://github.com/ismailops/recon-engine.git
cd recon-engine
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

---

## Usage

### Full scan

```bash
python main.py scan example.com
```

Runs subdomain enumeration, port scanning, and HTTP fingerprinting in sequence.
Results are persisted to `outputs/recon.db`.

### Subdomain enumeration

```bash
python main.py subdomains example.com
```

### Port scanning

```bash
python main.py ports example.com
python main.py ports example.com --ports 22,80,443,8080,8443
```

### Export and reporting

```bash
python main.py export example.com    # outputs/<target>_<timestamp>.json
python main.py report example.com    # outputs/<target>_<timestamp>_report.md
```

### Session history

```bash
python main.py sessions
```

### Options

| Flag | Description |
|---|---|
| `--ports` | Comma-separated port list. Default: 27 common ports. |
| `--verbose` | Enable DEBUG logging to stderr |
| `--no-confirm` | Skip authorization prompt (CI use) |

Full usage reference: [docs/usage.md](docs/usage.md)

---

## Running Tests

```bash
pytest tests/ -v
```

The test suite covers input validation, model constraints, database CRUD,
JSON export, and Markdown report generation. No network calls are made during tests.

---

## Security Notes

**This tool is for authorized security testing only.**
Scanning systems without explicit written permission is illegal in most jurisdictions.

Technical controls in the codebase:

- All user-supplied targets pass through `core/validator.py` before reaching any scanner.
  Shell metacharacters, path traversal sequences, and other hostile inputs are rejected.
- No `subprocess` calls with user-supplied arguments anywhere in the codebase.
- All database queries use parameterised statements. No string interpolation in SQL.
- HTTP requests include a descriptive User-Agent identifying the tool.
- Sensitive response headers (`Set-Cookie`, `Authorization`) are stripped before storage.
- Request timeouts are enforced on all network operations.
- No credentials, API keys, or secrets are required or stored.

---

## Roadmap

- DNS brute-force enumeration (wordlist-based, opt-in)
- Shodan and SecurityTrails integration for broader passive enumeration
- HTML report output
- CVSS-annotated findings for common exposures
- Rate limiting and scan throttle controls
- Concurrent multi-target scanning
- Docker image

---

## Screenshots

Screenshots showing CLI output for each command are located in `screenshots/`.
These will be replaced with actual terminal captures after the first production run.

| Screenshot | Description |
|---|---|
| `screenshots/scan_full.png` | Full scan output with Rich tables |
| `screenshots/subdomains.png` | Subdomain enumeration results |
| `screenshots/ports.png` | Port scan output with service names |
| `screenshots/report.md` | Sample generated Markdown report |

---

## License

MIT. See [LICENSE](LICENSE).
