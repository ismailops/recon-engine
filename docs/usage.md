# Usage

## Prerequisites

- Python 3.11+
- Dependencies installed: `pip install -r requirements.txt`
- Authorization to scan the target

## Commands

### Full Scan

Runs subdomain enumeration, port scanning, and HTTP fingerprinting in sequence.

```
python main.py scan <target> [--ports 22,80,443] [--verbose] [--no-confirm]
```

**Arguments**

| Argument | Description |
|---|---|
| target | Domain, IP address, or full URL |
| --ports | Comma-separated list of ports to scan. Defaults to 27 common ports. |
| --verbose | Enable DEBUG-level logging to stderr |
| --no-confirm | Skip the authorization confirmation prompt (useful in CI) |

**Examples**

```bash
# Full scan with default port list
python main.py scan example.com

# Full scan with custom ports
python main.py scan example.com --ports 22,80,443,8080,8443

# Full scan of a URL target (uses the URL's scheme and host)
python main.py scan https://example.com

# Full scan without interactive confirmation (CI use)
python main.py scan example.com --no-confirm
```

---

### Subdomain Enumeration Only

```
python main.py subdomains <target> [--verbose] [--no-confirm]
```

Queries crt.sh certificate transparency logs for the target domain.
Results are stored in the database.

```bash
python main.py subdomains example.com
```

---

### Port Scanning Only

```
python main.py ports <target> [--ports <list>] [--verbose] [--no-confirm]
```

```bash
# Scan default port list
python main.py ports 192.168.1.1

# Scan specific ports
python main.py ports example.com --ports 21,22,25,80,443,3306,5432
```

---

### Export to JSON

Exports the most recent scan session for the target to a JSON file in `outputs/`.

```
python main.py export <target>
```

```bash
python main.py export example.com
# Output: outputs/example_com_20240601_120000.json
```

---

### Generate Markdown Report

Generates a structured Markdown report from the most recent scan session.

```
python main.py report <target>
```

```bash
python main.py report example.com
# Output: outputs/example_com_20240601_120000_report.md
```

---

### List Sessions

Displays all scan sessions stored in the database.

```
python main.py sessions
```

---

## Default Port List

The default port list covers 27 commonly exposed services:

| Port | Service |
|---|---|
| 21 | FTP |
| 22 | SSH |
| 23 | Telnet |
| 25 | SMTP |
| 53 | DNS |
| 80 | HTTP |
| 110 | POP3 |
| 143 | IMAP |
| 443 | HTTPS |
| 445 | SMB |
| 1433 | MSSQL |
| 1521 | Oracle |
| 3306 | MySQL |
| 3389 | RDP |
| 5432 | PostgreSQL |
| 5900 | VNC |
| 6379 | Redis |
| 8080 | HTTP Alt |
| 8443 | HTTPS Alt |
| 9200 | Elasticsearch |
| 27017 | MongoDB |

(See `scanners/ports.py` for the full list.)

---

## Output Files

All output files are written to the `outputs/` directory.

| File | Description |
|---|---|
| `recon.db` | SQLite database (all sessions) |
| `<target>_<timestamp>.json` | JSON export |
| `<target>_<timestamp>_report.md` | Markdown report |

---

## Environment Variables

Copy `.env.example` to `.env` and configure as needed.

| Variable | Default | Description |
|---|---|---|
| RECON_DB_PATH | outputs/recon.db | SQLite database path |
| RECON_LOG_LEVEL | WARNING | Logging level (DEBUG, INFO, WARNING, ERROR) |

---

## Running Tests

```bash
pytest tests/ -v
```

To run a specific test file:

```bash
pytest tests/test_validator.py -v
pytest tests/test_store.py -v
pytest tests/test_export.py -v
pytest tests/test_models.py -v
```
