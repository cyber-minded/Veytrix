# Veytrix — Local Event Logging & PDF Reporting

A lightweight, self-contained module that stores security detection events in
a local SQLite database and produces professional PDF reports.

No cloud. No AI APIs. No GUI. No live monitoring. No detection rules.

Designed to be **imported by your detection layer** — you emit events, this
module stores them, searches them, applies retention, and exports reports.

---

## Quick start

```bash
# 1. Install the single dependency
pip install -r requirements.txt

# 2. Run the built-in test suite
python veytrix_logging.py --test

# 3. Generate a sample database + PDF
python veytrix_logging.py demo --outdir ./veytrix_demo
```

Result:
- `./veytrix_demo/events.db` — SQLite database with sample events
- `./veytrix_demo/report.pdf` — full PDF report

---

## Features

| Feature | Description |
|---|---|
| **`DetectionEvent`** | Strict contract with alias tolerance, validation, sanitization |
| **SQLite store** | WAL mode, versioned migrations, indexed search |
| **Search & filter** | By severity, min-severity, rule, host, process, source, time range, free text |
| **Retention** | Delete by age and/or max count, optional VACUUM |
| **PDF reports** | Executive summary, severity counts, per-event detail, process metadata, evidence |
| **Safe paths** | `safe_path()` blocks traversal, symlinks, wrong extensions |
| **Sanitized text** | Control chars stripped, length capped, XML-escaped in PDF |
| **Parameterized SQL** | No string concatenation anywhere |
| **CLI** | `init-db`, `ingest`, `report`, `retention`, `demo` |

Out of scope by design: **no GUI, no process monitoring, no network monitoring,
no file integrity monitoring, no quarantine, no detection rules** — those are
your application's job. This module is the *storage and reporting layer*.

---

## Requirements

- **Python ≥ 3.10**
- **`reportlab >= 4.0`** — required for PDF generation

Nothing else. No `psutil`, no `tkinter`, no OS-specific APIs.

---

## Install

```bash
pip install -r requirements.txt
```

---

## Integration into your code

```python
from veytrix_logging import DetectionEvent, EventDatabase, ReportGenerator

# 1. Build an event from your detection logic
event = DetectionEvent.from_mapping({
    "rule_id": "R-1001",
    "rule_name": "Encoded PowerShell",
    "severity": "high",
    "timestamp": "2024-06-01T12:34:56Z",
    "host": "WS-0142",
    "user": "CORP\\alice",
    "process": {
        "name": "powershell.exe",
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "pid": 5120,
        "cmdline": "powershell -nop -w hidden -enc SQBFAFgA",
    },
    "explanation": "Encoded commands hide intent.",
    "investigation_notes": "Decode payload; check egress.",
    "raw": {"session_id": 42},
})

# 2. Store it
with EventDatabase("events.db", base_dir="/var/lib/veytrix") as db:
    db.insert(event)

# 3. Later — search and report
with EventDatabase("events.db", base_dir="/var/lib/veytrix") as db:
    events = db.search(min_severity="high", limit=500)

ReportGenerator(base_dir="/var/lib/veytrix/reports").generate(
    events, "daily.pdf", title="Veytrix Daily Report")
```

---

## CLI usage

```bash
# Initialize an empty database
python veytrix_logging.py init-db --db events.db --base-dir ./data

# Ingest a JSON file (list of events or a single object)
python veytrix_logging.py ingest --db events.db --json events.json --base-dir ./data

# Generate a report filtered by severity and time range
python veytrix_logging.py report --db events.db --out report.pdf \
    --base-dir ./data --min-severity high \
    --since 2024-06-01T00:00:00Z --until 2024-06-30T23:59:59Z

# Apply retention (delete old / excess events)
python veytrix_logging.py retention --db events.db --base-dir ./data \
    --max-age-days 30 --max-events 100000 --vacuum

# Seed a sample database + PDF for testing
python veytrix_logging.py demo --outdir ./veytrix_demo
```

---

## Event schema (JSON accepted by `ingest`)

Only four fields are required: `rule_id`, `rule_name`, `severity`, `timestamp`.

```json
{
  "event_id": "evt-1001",
  "timestamp": "2024-06-01T12:34:56Z",
  "rule_id": "R-1001",
  "rule_name": "Encoded PowerShell",
  "severity": "high",
  "description": "PowerShell with Base64 payload.",
  "explanation": "Encoded commands hide intent.",
  "investigation_notes": "Decode payload; check egress.",
  "host": "WS-0142",
  "user": "CORP\\alice",
  "process": {
    "name": "powershell.exe",
    "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "pid": 5120,
    "ppid": 1024,
    "cmdline": "powershell -nop -w hidden -enc SQBFAFgA",
    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "source": "endpoint-edr",
  "raw": {"session_id": 42}
}
```

Accepted aliases (so you don't have to rename your fields):

| Canonical | Aliases |
|---|---|
| `rule_id` | `ruleId`, `id` |
| `rule_name` | `ruleName`, `detection_name`, `name`, `title` |
| `severity` | `risk_level`, `risk` |
| `timestamp` | `time`, `ts`, `occurred_at` |
| `process_cmdline` | `cmdline`, `command_line`, `command` |
| `process_pid` | `pid` |
| `process_ppid` | `ppid` |
| `process_hash` | `hash`, `sha256`, `md5` |
| `raw` | `raw_data`, `extra`, `metadata` |
| `description` | `summary`, `message` |
| `explanation` | `rationale`, `reason` |
| `investigation_notes` | `notes`, `investigationNotes` |
| `host` | `hostname`, `computer` |
| `user` | `username`, `user_name` |

---

## What the PDF report contains

1. **Cover page** — title, generation timestamp, time range, total count
2. **Executive summary** — severity table, top rules, top hosts
3. **Event index** — one row per event (severity, rule, host, process)
4. **Per-event detail pages** — one page per event:
   - Full process metadata table (host, user, source, name, path, PID, PPID, cmdline, hash)
   - Description
   - Explanation
   - Investigation notes
   - Raw data (optional, with `--include-raw`)

All text is XML-escaped before rendering — hostile input like `<script>` in a
rule name or `a < b & c > d` in a command line renders as literal text, not
markup, and never crashes the generator.

---

## Safety guarantees

- **Path safety** — every file write (DB and PDF) passes through `safe_path()`,
  which rejects:
  - absolute paths
  - `..` traversal
  - symlinks
  - wrong extensions when `--base-dir` is set
  - NUL bytes
- **Input sanitization** — all text fields have control characters stripped,
  newlines normalized, and length capped.
- **Parameterized SQL** — no string concatenation in any query.
- **XML escaping** — every string inserted into a PDF `Paragraph` is escaped.
- **Idempotent ingestion** — `INSERT OR IGNORE` on the unique `event_id` means
  re-ingesting the same JSON twice does not duplicate rows.
- **Migrations are additive and checked** — `schema_version` table tracks applied
  versions; running `connect()` multiple times is safe.

---

## Database layout

```
events
├── id                   INTEGER PRIMARY KEY AUTOINCREMENT
├── event_id             TEXT UNIQUE
├── timestamp            TEXT (ISO-8601 UTC)
├── rule_id              TEXT
├── rule_name            TEXT
├── severity             TEXT CHECK (low|medium|high|critical)
├── description          TEXT
├── explanation          TEXT
├── investigation_notes  TEXT
├── host                 TEXT
├── user                 TEXT
├── process_name         TEXT
├── process_path         TEXT
├── process_pid          INTEGER
├── process_ppid         INTEGER
├── process_cmdline      TEXT
├── process_hash         TEXT
├── source               TEXT
├── raw_json             TEXT
├── schema_version       INTEGER
└── inserted_at          TEXT

Indices:
  timestamp, severity, rule_id, host, process_name
```

---

## Testing

```bash
python veytrix_logging.py --test
```

Covers:

1. **Sanitization** — control chars stripped, truncation
2. **Validation** — missing fields, bad severity, bad timestamp, alias tolerance, negative PID
3. **Path safety** — absolute, traversal, bad extension, NUL byte
4. **Database** — insert, search by severity, duplicate handling, retention by age, retention by count, min-severity filter, text search, migration idempotency
5. **PDF** — file signature, size, hostile input (`<script>`, `<b>`, `a < b & c > d`), bad extension rejection

---

## Performance notes

Already applied:

- `PRAGMA journal_mode=WAL` — concurrent reads while writing
- `PRAGMA synchronous=NORMAL` — faster writes
- `busy_timeout=10000` — no immediate lock failures
- `temp_store=MEMORY` — faster sorts
- `executemany` inside a single `BEGIN IMMEDIATE` — bulk insert is one transaction
- `INSERT OR IGNORE` — duplicate detection is O(1) via unique index
- `apply_retention(..., vacuum=True)` — reclaims disk

For very large datasets, add an **FTS5** virtual table on `description` and
`explanation` to replace `LIKE '%...%'`.

---

## Known limitations

1. **No encryption at rest** — use full-disk encryption (LUKS / BitLocker).
2. **No full-text search index** — `--text` uses SQL `LIKE`, linear on huge DBs.
3. **PDF font is Helvetica** — CJK / emoji render as boxes. Register a TTF to fix.
4. **No PDF signing** — sign externally (GPG, PDF/A signer).
5. **Single-writer SQLite** — multi-process ingestion serializes on `BEGIN IMMEDIATE`.
6. **Retention deletes are irreversible** — back up before calling `apply_retention`.
7. **No deduplication of stored events** — every `INSERT OR IGNORE` at the DB
   level only dedupes by `event_id`. If your detection layer emits *the same
   alert* with different `event_id`s, they will all be stored. Dedupe is the
   caller's responsibility at this layer.

---

## File

Single file: **`veytrix_logging.py`**. Import it, or run it as a script.

---

## License

MIT.
