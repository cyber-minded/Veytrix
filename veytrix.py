"""
veytrix_logging.py
==================

Veytrix local SQLite event logging and PDF report generator.

Scope
-----
- Accept `DetectionEvent` objects (dict/object) from the shared technical contract.
- Persist to local SQLite with schema migrations, indices, retention.
- Search / filter / paginate events via parameterized queries.
- Generate professional PDF reports with ReportLab.
- Defensive validation, text sanitization, safe file paths, safe DB ops.

Out of scope (by requirement)
-----------------------------
- No GUI, no process monitoring, no detection rules.
- No AI APIs, no cloud services.

Quick start
-----------
    python veytrix_logging.py demo --outdir ./veytrix_demo
    python veytrix_logging.py --test
    python veytrix_logging.py init-db --db events.db --base-dir ./data
    python veytrix_logging.py ingest --db events.db --json events.json --base-dir ./data
    python veytrix_logging.py report --db events.db --out report.pdf --base-dir ./data --min-severity high
    python veytrix_logging.py retention --db events.db --base-dir ./data --max-age-days 30 --vacuum
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import unittest
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Optional, Sequence

from xml.sax.saxutils import escape as xml_escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

__version__ = "1.0.0"
APP_NAME = "Veytrix"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_LEVELS: tuple[str, ...] = ("low", "medium", "high", "critical")
_SEVERITY_RANK: dict[str, int] = {s: i + 1 for i, s in enumerate(SEVERITY_LEVELS)}

MAX_TEXT_LEN = 8_000
MAX_RAW_LEN = 64_000
MAX_ID_LEN = 128
DEFAULT_PAGE_SIZE = 100

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ValidationError(ValueError):
    """Raised when malformed event data is supplied."""


class SecurityError(RuntimeError):
    """Raised on unsafe file paths or unsafe operations."""


# ---------------------------------------------------------------------------
# Helpers: sanitization, timestamps, coercion
# ---------------------------------------------------------------------------

def sanitize_text(value: Any, max_len: int = MAX_TEXT_LEN) -> str:
    """Remove control characters, normalize newlines, and cap length."""
    if value is None:
        return ""
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:
            value = repr(value)
    value = _CONTROL_RE.sub("", value)
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    if max_len and len(value) > max_len:
        value = value[:max_len] + "…[truncated]"
    return value


def _now_utc_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _normalize_timestamp(value: Any) -> str:
    if value is None:
        raise ValidationError("timestamp is required")
    if isinstance(value, dt.datetime):
        d = value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
        return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, str):
        s = value.strip()
        if not s:
            raise ValidationError("timestamp is empty")
        iso = s[:-1] + "+00:00" if s.endswith("Z") else s
        try:
            d = dt.datetime.fromisoformat(iso)
        except ValueError as exc:
            raise ValidationError(f"invalid timestamp {value!r}: {exc}") from exc
        if d.tzinfo is None:
            d = d.replace(tzinfo=dt.timezone.utc)
        return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    raise ValidationError(f"unsupported timestamp type: {type(value).__name__}")


def _coerce_pid(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValidationError("pid must not be bool")
    try:
        v = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"invalid pid {value!r}") from exc
    if v < 0:
        raise ValidationError(f"pid must be non-negative, got {v}")
    return v


def _coerce_severity(value: Any) -> str:
    if value is None:
        raise ValidationError("severity is required")
    s = str(value).strip().lower()
    if s not in SEVERITY_LEVELS:
        raise ValidationError(f"severity must be one of {SEVERITY_LEVELS}, got {value!r}")
    return s


def _coerce_json_dict(value: Any) -> dict:
    if value is None:
        return {}
    if isinstance(value, dict):
        data = value
    elif isinstance(value, str):
        try:
            data = json.loads(value)
        except Exception as exc:
            raise ValidationError(f"raw must be valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValidationError("raw JSON must be an object")
    else:
        try:
            data = dict(value)
        except Exception as exc:
            raise ValidationError(f"raw must be a mapping: {exc}") from exc
    try:
        encoded = json.dumps(data, default=str, ensure_ascii=False)
    except Exception:
        encoded = json.dumps({"_repr": repr(data)}, ensure_ascii=False)
    if len(encoded) > MAX_RAW_LEN:
        return {"_truncated": True, "_preview": encoded[:MAX_RAW_LEN]}
    return data


def _get_any(obj: Any, keys: Sequence[str], default: Any = None) -> Any:
    for key in keys:
        if isinstance(obj, dict):
            if key in obj and obj[key] is not None:
                return obj[key]
        elif hasattr(obj, key):
            v = getattr(obj, key)
            if v is not None:
                return v
    return default


# ---------------------------------------------------------------------------
# DetectionEvent contract
# ---------------------------------------------------------------------------

@dataclass
class DetectionEvent:
    """The shared technical contract for detection events.

    Accepts dict-like mappings or objects; see `from_mapping`.
    """

    event_id: str
    timestamp: str
    rule_id: str
    rule_name: str
    severity: str
    description: str = ""
    explanation: str = ""
    investigation_notes: str = ""
    host: str = ""
    user: str = ""
    process_name: str = ""
    process_path: str = ""
    process_pid: Optional[int] = None
    process_ppid: Optional[int] = None
    process_cmdline: str = ""
    process_hash: str = ""
    source: str = ""
    raw: dict = field(default_factory=dict)
    schema_version: int = 1

    # Order matches `events` table column order (excluding auto id/inserted_at).
    COLUMNS: tuple[str, ...] = (
        "event_id", "timestamp", "rule_id", "rule_name", "severity",
        "description", "explanation", "investigation_notes", "host", "user",
        "process_name", "process_path", "process_pid", "process_ppid",
        "process_cmdline", "process_hash", "source", "raw_json",
        "schema_version",
    )

    @classmethod
    def from_mapping(cls, obj: Any) -> "DetectionEvent":
        """Validate and normalize arbitrary mapping/object into a DetectionEvent.

        Recognizes common aliases (e.g., `risk_level`, `detection_name`, `time`)
        to be tolerant of variations in the shared technical contract.
        """
        if obj is None or not (isinstance(obj, dict) or hasattr(obj, "__dict__")):
            raise ValidationError(
                f"DetectionEvent requires mapping/object, got {type(obj).__name__}"
            )

        rule_id = _get_any(obj, ("rule_id", "ruleId", "id"))
        rule_name = _get_any(obj, ("rule_name", "ruleName", "detection_name", "name", "title"))
        if rule_id is None or not str(rule_id).strip():
            raise ValidationError("rule_id is required")
        if rule_name is None or not str(rule_name).strip():
            raise ValidationError("rule_name is required")

        timestamp = _normalize_timestamp(_get_any(obj, ("timestamp", "time", "ts", "occurred_at")))
        severity = _coerce_severity(_get_any(obj, ("severity", "risk_level", "risk")))

        raw_id = _get_any(obj, ("event_id", "eventId", "id"))
        event_id = sanitize_text(str(raw_id), max_len=MAX_ID_LEN) if raw_id is not None else str(uuid.uuid4())
        if not event_id:
            raise ValidationError("event_id cannot be empty")

        proc = _get_any(obj, ("process",), None)
        if proc is not None and not isinstance(proc, dict) and hasattr(proc, "__dict__"):
            proc = vars(proc)
        if not isinstance(proc, dict):
            proc = {}

        def proc_field(*names: str, default: Any = None) -> Any:
            for n in names:
                if n in proc and proc[n] is not None:
                    return proc[n]
            return default

        pname = _get_any(obj, ("process_name", "processName"),
                         proc_field("name", "process_name", "image"))
        ppath = _get_any(obj, ("process_path", "processPath"),
                         proc_field("path", "image_path", "process_path"))
        ppid = _get_any(obj, ("process_pid", "processPid", "pid"),
                        proc_field("pid", "process_pid"))
        pppid = _get_any(obj, ("process_ppid", "processPpid", "ppid"),
                         proc_field("ppid", "parent_pid"))
        pcmd = _get_any(obj, ("process_cmdline", "processCmdline", "cmdline"),
                        proc_field("cmdline", "command_line", "command"))
        phash = _get_any(obj, ("process_hash", "processHash", "hash"),
                         proc_field("hash", "sha256", "md5"))
        raw = _coerce_json_dict(_get_any(obj, ("raw", "raw_data", "extra", "metadata")))

        return cls(
            event_id=event_id,
            timestamp=timestamp,
            rule_id=sanitize_text(str(rule_id), max_len=MAX_ID_LEN),
            rule_name=sanitize_text(str(rule_name)),
            severity=severity,
            description=sanitize_text(_get_any(obj, ("description", "summary", "message"), "")),
            explanation=sanitize_text(_get_any(obj, ("explanation", "rationale", "reason"), "")),
            investigation_notes=sanitize_text(
                _get_any(obj, ("investigation_notes", "notes", "investigationNotes"), "")
            ),
            host=sanitize_text(_get_any(obj, ("host", "hostname", "computer"), "")),
            user=sanitize_text(_get_any(obj, ("user", "username", "user_name"), "")),
            process_name=sanitize_text(pname or ""),
            process_path=sanitize_text(ppath or ""),
            process_pid=_coerce_pid(ppid),
            process_ppid=_coerce_pid(pppid),
            process_cmdline=sanitize_text(pcmd or ""),
            process_hash=sanitize_text(phash or "", max_len=256),
            source=sanitize_text(_get_any(obj, ("source", "sensor"), "")),
            raw=raw,
            schema_version=int(_get_any(obj, ("schema_version",), 1) or 1),
        )

    def to_row(self) -> tuple:
        return (
            self.event_id, self.timestamp, self.rule_id, self.rule_name,
            self.severity, self.description, self.explanation,
            self.investigation_notes, self.host, self.user,
            self.process_name, self.process_path, self.process_pid,
            self.process_ppid, self.process_cmdline, self.process_hash,
            self.source,
            json.dumps(self.raw, default=str, ensure_ascii=False),
            self.schema_version,
        )

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "DetectionEvent":
        raw_json = row["raw_json"] or "{}"
        try:
            raw = json.loads(raw_json) if raw_json else {}
        except Exception:
            raw = {"_parse_error": True, "_raw": raw_json}
        return cls(
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            rule_id=row["rule_id"],
            rule_name=row["rule_name"],
            severity=row["severity"],
            description=row["description"] or "",
            explanation=row["explanation"] or "",
            investigation_notes=row["investigation_notes"] or "",
            host=row["host"] or "",
            user=row["user"] or "",
            process_name=row["process_name"] or "",
            process_path=row["process_path"] or "",
            process_pid=row["process_pid"],
            process_ppid=row["process_ppid"],
            process_cmdline=row["process_cmdline"] or "",
            process_hash=row["process_hash"] or "",
            source=row["source"] or "",
            raw=raw if isinstance(raw, dict) else {"_value": raw},
            schema_version=row["schema_version"] or 1,
        )


# ---------------------------------------------------------------------------
# Safe path handling
# ---------------------------------------------------------------------------

def safe_path(
    base_dir: str,
    filename: str,
    *,
    allowed_extensions: Optional[Sequence[str]] = None,
    create_base: bool = False,
) -> str:
    """Resolve `filename` under `base_dir`, rejecting traversal and unsafe paths."""
    if not isinstance(filename, str) or not filename:
        raise SecurityError("filename must be a non-empty string")
    if "\x00" in filename:
        raise SecurityError("filename contains NUL byte")

    base = os.path.realpath(os.path.abspath(base_dir))
    if not os.path.isdir(base):
        if create_base:
            os.makedirs(base, mode=0o700, exist_ok=True)
            base = os.path.realpath(base)
        else:
            raise SecurityError(f"base directory does not exist: {base_dir}")

    if os.path.isabs(filename) or (os.name == "nt" and os.path.splitdrive(filename)[0]):
        raise SecurityError(f"absolute path not allowed: {filename!r}")

    norm = os.path.normpath(filename)
    if norm == ".." or norm.startswith(".." + os.sep):
        raise SecurityError(f"path traversal not allowed: {filename!r}")

    target = os.path.realpath(os.path.join(base, norm))
    if not (target == base or target.startswith(base + os.sep)):
        raise SecurityError(f"resolved path escapes base: {target!r}")

    if allowed_extensions:
        ext = os.path.splitext(target)[1].lower()
        allowed = {e.lower() for e in allowed_extensions}
        if ext not in allowed:
            raise SecurityError(f"extension {ext!r} not allowed, permitted: {sorted(allowed)}")

    if os.path.islink(target):
        raise SecurityError(f"refusing to write to symlink: {target!r}")

    return target


# ---------------------------------------------------------------------------
# SQLite schema & migrations
# ---------------------------------------------------------------------------

# Each migration is (version, [statements]). Applied in order.
MIGRATIONS: list[tuple[int, list[str]]] = [
    (1, [
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
            description TEXT NOT NULL DEFAULT '',
            explanation TEXT NOT NULL DEFAULT '',
            investigation_notes TEXT NOT NULL DEFAULT '',
            host TEXT NOT NULL DEFAULT '',
            user TEXT NOT NULL DEFAULT '',
            process_name TEXT NOT NULL DEFAULT '',
            process_path TEXT NOT NULL DEFAULT '',
            process_pid INTEGER,
            process_ppid INTEGER,
            process_cmdline TEXT NOT NULL DEFAULT '',
            process_hash TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            raw_json TEXT NOT NULL DEFAULT '{}',
            schema_version INTEGER NOT NULL DEFAULT 1,
            inserted_at TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)",
        "CREATE INDEX IF NOT EXISTS idx_events_rule_id ON events(rule_id)",
        "CREATE INDEX IF NOT EXISTS idx_events_host ON events(host)",
        "CREATE INDEX IF NOT EXISTS idx_events_process_name ON events(process_name)",
    ]),
]


class EventDatabase:
    """SQLite-backed event store with migrations, indexing, and retention."""

    def __init__(
        self,
        db_path: str,
        *,
        base_dir: Optional[str] = None,
        create_base: bool = True,
        timeout: float = 10.0,
    ):
        if base_dir is not None:
            self.db_path = safe_path(
                base_dir, db_path,
                allowed_extensions={".db", ".sqlite", ".sqlite3"},
                create_base=create_base,
            )
        else:
            self.db_path = os.path.realpath(os.path.abspath(db_path))
            ext = os.path.splitext(self.db_path)[1].lower()
            if ext not in (".db", ".sqlite", ".sqlite3"):
                raise SecurityError(
                    f"database must have .db/.sqlite/.sqlite3 extension, got {ext!r}"
                )
        self._conn: Optional[sqlite3.Connection] = None
        self._timeout = timeout

    # -- lifecycle ---------------------------------------------------------

    def connect(self) -> "EventDatabase":
        if self._conn is not None:
            return self
        parent = os.path.dirname(self.db_path)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent, mode=0o700, exist_ok=True)
        conn = sqlite3.connect(self.db_path, timeout=self._timeout, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA temp_store=MEMORY")
        self._conn = conn
        self._migrate()
        return self

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "EventDatabase":
        return self.connect()

    def __exit__(self, *exc: Any) -> None:
        self.close()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self.connect()
        assert self._conn is not None
        return self._conn

    # -- migrations --------------------------------------------------------

    def _migrate(self) -> None:
        conn = self._conn
        assert conn is not None
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """
        )
        current = int(
            conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_version").fetchone()[0]
        )
        for version, statements in MIGRATIONS:
            if version <= current:
                continue
            conn.execute("BEGIN IMMEDIATE")
            try:
                for stmt in statements:
                    conn.execute(stmt)
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (version, _now_utc_iso()),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

    # -- transaction helper ------------------------------------------------

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
        conn = self.conn
        cur = conn.cursor()
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield cur
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            cur.close()

    # -- writes ------------------------------------------------------------

    def insert_many(
        self, events: Iterable[DetectionEvent], *, replace: bool = False
    ) -> int:
        now = _now_utc_iso()
        rows = [e.to_row() + (now,) for e in events]
        if not rows:
            return 0
        verb = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
        cols = ",".join(DetectionEvent.COLUMNS) + ",inserted_at"
        ph = ",".join("?" for _ in range(len(DetectionEvent.COLUMNS) + 1))
        sql = f"{verb} INTO events ({cols}) VALUES ({ph})"
        with self.transaction() as cur:
            before = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            cur.executemany(sql, rows)
            after = cur.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        return int(after - before)

    def insert(self, event: DetectionEvent, *, replace: bool = False) -> bool:
        return self.insert_many([event], replace=replace) == 1

    # -- reads -------------------------------------------------------------

    def search(
        self,
        *,
        severity: Optional[Any] = None,
        min_severity: Optional[str] = None,
        rule_id: Optional[str] = None,
        host: Optional[str] = None,
        process_name: Optional[str] = None,
        source: Optional[str] = None,
        since: Optional[Any] = None,
        until: Optional[Any] = None,
        text: Optional[str] = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
        order: str = "desc",
    ) -> list[DetectionEvent]:
        if limit is None or limit < 0:
            raise ValueError("limit must be non-negative")
        limit = min(int(limit), 10_000)
        if offset < 0:
            raise ValueError("offset must be non-negative")

        clauses: list[str] = []
        params: list[Any] = []

        if severity is not None:
            sevs = [severity] if isinstance(severity, str) else list(severity)
            sevs = [_coerce_severity(s) for s in sevs]
            clauses.append("severity IN ({})".format(",".join("?" * len(sevs))))
            params.extend(sevs)

        if min_severity is not None:
            rank = _SEVERITY_RANK[_coerce_severity(min_severity)]
            allowed = [s for s, r in _SEVERITY_RANK.items() if r >= rank]
            clauses.append("severity IN ({})".format(",".join("?" * len(allowed))))
            params.extend(allowed)

        if rule_id is not None:
            clauses.append("rule_id = ?")
            params.append(str(rule_id))
        if host is not None:
            clauses.append("host = ?")
            params.append(str(host))
        if process_name is not None:
            clauses.append("process_name = ?")
            params.append(str(process_name))
        if source is not None:
            clauses.append("source = ?")
            params.append(str(source))
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(_normalize_timestamp(since))
        if until is not None:
            clauses.append("timestamp <= ?")
            params.append(_normalize_timestamp(until))
        if text:
            like = f"%{sanitize_text(text, max_len=500)}%"
            clauses.append(
                "(description LIKE ? OR explanation LIKE ? "
                "OR rule_name LIKE ? OR investigation_notes LIKE ?)"
            )
            params.extend([like] * 4)

        sql = "SELECT * FROM events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        direction = "ASC" if str(order).lower() == "asc" else "DESC"
        sql += f" ORDER BY timestamp {direction}, id {direction} LIMIT ? OFFSET ?"
        params.extend([limit, int(offset)])

        rows = self.conn.execute(sql, params).fetchall()
        return [DetectionEvent.from_row(r) for r in rows]

    def count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    # -- retention ---------------------------------------------------------

    def apply_retention(
        self,
        *,
        max_age_days: Optional[int] = None,
        max_events: Optional[int] = None,
        vacuum: bool = False,
    ) -> dict:
        if max_age_days is not None and max_age_days < 0:
            raise ValueError("max_age_days must be >= 0")
        if max_events is not None and max_events < 0:
            raise ValueError("max_events must be >= 0")

        deleted = 0
        with self.transaction() as cur:
            if max_age_days is not None:
                cutoff = (
                    dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=max_age_days)
                ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                cur.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,))
                if cur.rowcount > 0:
                    deleted += cur.rowcount
            if max_events is not None:
                cur.execute(
                    """
                    DELETE FROM events WHERE id NOT IN (
                        SELECT id FROM events ORDER BY timestamp DESC, id DESC LIMIT ?
                    )
                    """,
                    (int(max_events),),
                )
                if cur.rowcount > 0:
                    deleted += cur.rowcount
        if vacuum:
            self.conn.execute("VACUUM")
        return {"deleted": deleted, "remaining": self.count()}


# ---------------------------------------------------------------------------
# PDF report generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Generate professional PDF reports from DetectionEvent sequences."""

    def __init__(self, *, base_dir: Optional[str] = None):
        self.base_dir = base_dir
        self._styles = self._build_styles()

    # -- styles ------------------------------------------------------------

    def _build_styles(self) -> dict[str, ParagraphStyle]:
        base = getSampleStyleSheet()
        return {
            "title": ParagraphStyle(
                "VxTitle", parent=base["Title"], fontName="Helvetica-Bold",
                fontSize=20, leading=24, alignment=TA_LEFT,
                textColor=colors.HexColor("#0B1F3A"), spaceAfter=4,
            ),
            "subtitle": ParagraphStyle(
                "VxSubtitle", parent=base["Normal"], fontName="Helvetica",
                fontSize=11, leading=14, textColor=colors.HexColor("#44546A"),
                spaceAfter=2,
            ),
            "meta": ParagraphStyle(
                "VxMeta", parent=base["Normal"], fontName="Helvetica",
                fontSize=9, leading=12, textColor=colors.grey,
            ),
            "h2": ParagraphStyle(
                "VxH2", parent=base["Heading2"], fontName="Helvetica-Bold",
                fontSize=14, leading=18, textColor=colors.HexColor("#0B1F3A"),
                spaceBefore=8, spaceAfter=6,
            ),
            "h3": ParagraphStyle(
                "VxH3", parent=base["Heading3"], fontName="Helvetica-Bold",
                fontSize=11, leading=14, textColor=colors.HexColor("#1F3A5F"),
                spaceBefore=6, spaceAfter=3,
            ),
            "body": ParagraphStyle(
                "VxBody", parent=base["Normal"], fontName="Helvetica",
                fontSize=9.5, leading=13, splitLongWords=1,
            ),
            "mono": ParagraphStyle(
                "VxMono", parent=base["Normal"], fontName="Courier",
                fontSize=8, leading=10, wordWrap="CJK",
            ),
            "label": ParagraphStyle(
                "VxLabel", parent=base["Normal"], fontName="Helvetica-Bold",
                fontSize=9, leading=12, textColor=colors.HexColor("#44546A"),
            ),
        }

    # -- footer ------------------------------------------------------------

    @staticmethod
    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawString(18 * mm, 10 * mm, f"{APP_NAME} — Confidential")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    # -- public API --------------------------------------------------------

    def generate(
        self,
        events: Sequence[DetectionEvent],
        output_path: str,
        *,
        title: str = "Veytrix Detection Report",
        subtitle: Optional[str] = None,
        include_raw: bool = False,
    ) -> str:
        if self.base_dir is not None:
            target = safe_path(
                self.base_dir, output_path,
                allowed_extensions={".pdf"}, create_base=True,
            )
        else:
            target = os.path.realpath(os.path.abspath(output_path))
            if os.path.splitext(target)[1].lower() != ".pdf":
                raise SecurityError("output path must end in .pdf")
            parent = os.path.dirname(target)
            if parent:
                os.makedirs(parent, exist_ok=True)

        events = list(events)
        doc = SimpleDocTemplate(
            target,
            pagesize=A4,
            leftMargin=18 * mm, rightMargin=18 * mm,
            topMargin=18 * mm, bottomMargin=18 * mm,
            title=sanitize_text(title, 200),
            author=APP_NAME,
            subject="Detection Report",
        )

        story: list = []
        story.extend(self._cover(title, subtitle, events))
        story.extend(self._summary(events))
        story.extend(self._index(events))
        story.append(PageBreak())
        for i, ev in enumerate(events, 1):
            story.extend(self._detail(i, ev, include_raw))

        doc.build(story, onFirstPage=self._footer, onLaterPages=self._footer)
        return target

    # -- section builders --------------------------------------------------

    def _cover(
        self, title: str, subtitle: Optional[str], events: Sequence[DetectionEvent]
    ) -> list:
        out: list = [Spacer(1, 6 * mm)]
        out.append(Paragraph(xml_escape(sanitize_text(title, 200)), self._styles["title"]))
        if subtitle:
            out.append(Paragraph(xml_escape(sanitize_text(subtitle, 200)), self._styles["subtitle"]))
        out.append(Paragraph(f"Generated: {xml_escape(_now_utc_iso())}", self._styles["meta"]))
        if events:
            ts_sorted = sorted(e.timestamp for e in events)
            out.append(Paragraph(
                f"Time range: {xml_escape(ts_sorted[0])} &rarr; {xml_escape(ts_sorted[-1])}",
                self._styles["meta"],
            ))
        out.append(Paragraph(f"Total events: {len(events)}", self._styles["meta"]))
        out.append(Spacer(1, 6 * mm))
        return out

    def _summary(self, events: Sequence[DetectionEvent]) -> list:
        out: list = [Paragraph("Executive Summary", self._styles["h2"])]
        counts = {s: 0 for s in SEVERITY_LEVELS}
        by_rule: dict[str, int] = {}
        by_host: dict[str, int] = {}
        for e in events:
            counts[e.severity] = counts.get(e.severity, 0) + 1
            by_rule[e.rule_id] = by_rule.get(e.rule_id, 0) + 1
            if e.host:
                by_host[e.host] = by_host.get(e.host, 0) + 1

        data = [["Severity", "Count"]]
        for s in reversed(SEVERITY_LEVELS):
            data.append([s.upper(), str(counts.get(s, 0))])
        data.append(["TOTAL", str(sum(counts.values()))])

        tbl = Table(data, colWidths=[60 * mm, 30 * mm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B1F3A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7FA")]),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        out.append(tbl)
        out.append(Spacer(1, 4 * mm))

        if by_rule:
            out.append(Paragraph("Top Rules", self._styles["h3"]))
            top = sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
            t = Table(
                [["Rule ID", "Hits"]] + [[xml_escape(str(r)), str(c)] for r, c in top],
                colWidths=[70 * mm, 25 * mm],
            )
            t.setStyle(self._simple_table_style())
            out.append(t)
            out.append(Spacer(1, 3 * mm))

        if by_host:
            out.append(Paragraph("Top Hosts", self._styles["h3"]))
            top = sorted(by_host.items(), key=lambda kv: (-kv[1], kv[0]))[:10]
            t = Table(
                [["Host", "Events"]] + [[xml_escape(str(h)), str(c)] for h, c in top],
                colWidths=[70 * mm, 25 * mm],
            )
            t.setStyle(self._simple_table_style())
            out.append(t)

        out.append(Spacer(1, 4 * mm))
        return out

    @staticmethod
    def _simple_table_style() -> TableStyle:
        return TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3A5F")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7FA")]),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])

    def _index(self, events: Sequence[DetectionEvent]) -> list:
        out: list = [Spacer(1, 4 * mm), Paragraph("Event Index", self._styles["h2"])]
        rows = [["#", "Timestamp (UTC)", "Severity", "Rule", "Host", "Process"]]
        for i, e in enumerate(events, 1):
            rows.append([
                str(i),
                e.timestamp[:19].replace("T", " "),
                e.severity.upper(),
                xml_escape(e.rule_id[:40]),
                xml_escape((e.host or "-")[:30]),
                xml_escape((e.process_name or "-")[:30]),
            ])
        t = Table(
            rows,
            colWidths=[8 * mm, 34 * mm, 18 * mm, 32 * mm, 32 * mm, 32 * mm],
            repeatRows=1,
        )
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B1F3A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.lightgrey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F7FA")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        out.append(t)
        return out

    def _detail(
        self, idx: int, ev: DetectionEvent, include_raw: bool
    ) -> list:
        out: list = []
        header = f"Event #{idx} — {ev.rule_name} [{ev.severity.upper()}]"
        out.append(Paragraph(xml_escape(sanitize_text(header, 300)), self._styles["h2"]))
        out.append(Paragraph(f"Event ID: {xml_escape(ev.event_id)}", self._styles["meta"]))
        out.append(Paragraph(f"Timestamp (UTC): {xml_escape(ev.timestamp)}", self._styles["meta"]))
        out.append(Paragraph(
            f"Rule: {xml_escape(ev.rule_id)} &mdash; {xml_escape(ev.rule_name)}",
            self._styles["body"],
        ))
        out.append(Paragraph(
            f"Severity: <b>{xml_escape(ev.severity.upper())}</b>",
            self._styles["body"],
        ))
        out.append(Spacer(1, 2 * mm))

        rows = [["Field", "Value"]]
        proc_fields = [
            ("Host", ev.host),
            ("User", ev.user),
            ("Source", ev.source),
            ("Process Name", ev.process_name),
            ("Process Path", ev.process_path),
            ("PID", "" if ev.process_pid is None else str(ev.process_pid)),
            ("PPID", "" if ev.process_ppid is None else str(ev.process_ppid)),
            ("Command Line", ev.process_cmdline),
            ("Hash", ev.process_hash),
        ]
        for k, v in proc_fields:
            rows.append([k, v if v not in (None, "") else "—"])
        t = Table(rows, colWidths=[40 * mm, 120 * mm])
        t.setStyle(self._simple_table_style())
        out.append(t)
        out.append(Spacer(1, 2 * mm))

        out.append(self._text_block("Description", ev.description))
        out.append(self._text_block("Explanation", ev.explanation))
        out.append(self._text_block("Investigation Notes", ev.investigation_notes))

        if include_raw and ev.raw:
            raw_str = json.dumps(ev.raw, indent=2, default=str, ensure_ascii=False)
            out.append(self._text_block("Raw Data", raw_str, mono=True))

        out.append(Spacer(1, 5 * mm))
        return out

    def _text_block(self, label: str, text: str, mono: bool = False) -> KeepTogether:
        style = self._styles["mono"] if mono else self._styles["body"]
        safe = xml_escape(sanitize_text(text or "", 20_000)).replace("\n", "<br/>")
        return KeepTogether([
            Paragraph(label, self._styles["label"]),
            Paragraph(safe or "—", style),
            Spacer(1, 1.5 * mm),
        ])


# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

def make_sample_events() -> list[DetectionEvent]:
    now = dt.datetime.now(dt.timezone.utc)

    def t(minutes_ago: int) -> str:
        return (now - dt.timedelta(minutes=minutes_ago)).isoformat()

    samples = [
        {
            "event_id": "evt-1001",
            "timestamp": t(120),
            "rule_id": "R-1001",
            "rule_name": "Suspicious PowerShell Encoded Command",
            "severity": "high",
            "description": "PowerShell was launched with a Base64-encoded payload.",
            "explanation": "Encoded commands are a common obfuscation technique "
                           "used to hide malicious intent.",
            "investigation_notes": "Decode payload and check network egress.",
            "host": "WS-0142",
            "user": "CORP\\alice",
            "process": {
                "name": "powershell.exe",
                "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "pid": 5120,
                "ppid": 1024,
                "cmdline": "powershell -nop -w hidden -enc SQBFAFgA...",
                "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            },
            "source": "endpoint-edr",
            "raw": {"session_id": 42, "user_sid": "S-1-5-21-..."},
        },
        {
            "event_id": "evt-1002",
            "timestamp": t(60),
            "rule_id": "R-2002",
            "rule_name": "Credential Dumping via LSASS Access",
            "severity": "critical",
            "description": "Non-standard process accessed LSASS memory.",
            "explanation": "Direct LSASS access with read permissions is highly "
                           "suspicious and consistent with credential dumping.",
            "investigation_notes": "Isolate host immediately and pull memory image.",
            "host": "WS-0177",
            "user": "CORP\\bob",
            "process": {
                "name": "mimikatz.exe",
                "path": "C:\\Users\\Public\\mimikatz.exe",
                "pid": 8844,
                "ppid": 4200,
                "cmdline": "mimikatz.exe sekurlsa::logonpasswords",
                "hash": "8f14e45fceea167a5a36dedd4bea2543",
            },
            "source": "endpoint-edr",
        },
        {
            "event_id": "evt-1003",
            "timestamp": t(30),
            "rule_id": "R-3003",
            "rule_name": "Unusual Outbound Connection",
            "severity": "medium",
            "description": "Process made outbound connection to untrusted ASN.",
            "explanation": "First-seen remote endpoint at unusual hour.",
            "host": "SRV-DC-01",
            "user": "NT AUTHORITY\\SYSTEM",
            "process": {"name": "svchost.exe", "pid": 908},
            "source": "network-monitor",
        },
        {
            "event_id": "evt-1004",
            "timestamp": t(15),
            "rule_id": "R-4004",
            "rule_name": "Registry Run Key Persistence",
            "severity": "low",
            "description": "New Run key entry observed on workstation.",
            "explanation": "Common autorun location; may be benign or malicious.",
            "investigation_notes": "Confirm with user and verify binary signature.",
            "host": "WS-0101",
            "user": "CORP\\carol",
            "process": {"name": "reg.exe", "pid": 2244},
            "source": "endpoint-edr",
        },
    ]
    return [DetectionEvent.from_mapping(s) for s in samples]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli(argv: Optional[Sequence[str]] = None) -> None:
    p = argparse.ArgumentParser(
        prog="veytrix_logging",
        description="Veytrix local SQLite logging + PDF report generator",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_db = sub.add_parser("init-db", help="initialize database")
    p_db.add_argument("--db", required=True)
    p_db.add_argument("--base-dir")

    p_ing = sub.add_parser("ingest", help="ingest JSON event file (list or single object)")
    p_ing.add_argument("--db", required=True)
    p_ing.add_argument("--json", required=True)
    p_ing.add_argument("--base-dir")

    p_rep = sub.add_parser("report", help="build PDF report")
    p_rep.add_argument("--db", required=True)
    p_rep.add_argument("--out", required=True)
    p_rep.add_argument("--base-dir")
    p_rep.add_argument("--severity")
    p_rep.add_argument("--min-severity")
    p_rep.add_argument("--since")
    p_rep.add_argument("--until")
    p_rep.add_argument("--limit", type=int, default=500)
    p_rep.add_argument("--title", default="Veytrix Detection Report")
    p_rep.add_argument("--include-raw", action="store_true")

    p_ret = sub.add_parser("retention", help="apply retention policy")
    p_ret.add_argument("--db", required=True)
    p_ret.add_argument("--max-age-days", type=int)
    p_ret.add_argument("--max-events", type=int)
    p_ret.add_argument("--vacuum", action="store_true")
    p_ret.add_argument("--base-dir")

    p_demo = sub.add_parser("demo", help="create sample DB + report under --outdir")
    p_demo.add_argument("--outdir", default="./veytrix_demo")

    args = p.parse_args(argv)

    if args.cmd == "demo":
        outdir = os.path.realpath(os.path.abspath(args.outdir))
        os.makedirs(outdir, mode=0o700, exist_ok=True)
        db = EventDatabase("events.db", base_dir=outdir, create_base=True)
        with db:
            inserted = db.insert_many(make_sample_events())
            events = db.search(limit=500)
            report = ReportGenerator(base_dir=outdir).generate(
                events, "report.pdf",
                title="Veytrix Detection Report",
                subtitle="Demonstration report",
                include_raw=True,
            )
        print(f"Inserted {inserted} events")
        print(f"Database: {db.db_path}")
        print(f"Report:   {report}")
        return

    base_dir = getattr(args, "base_dir", None)

    if args.cmd == "init-db":
        with EventDatabase(args.db, base_dir=base_dir):
            print(f"Initialized: {args.db}")
        return

    if args.cmd == "ingest":
        with open(args.json, "r", encoding="utf-8") as f:
            payload = json.load(f)
        records = payload if isinstance(payload, list) else [payload]
        events: list[DetectionEvent] = []
        for i, rec in enumerate(records):
            try:
                events.append(DetectionEvent.from_mapping(rec))
            except ValidationError as exc:
                print(f"[skip] record {i}: {exc}", file=sys.stderr)
        with EventDatabase(args.db, base_dir=base_dir) as db:
            n = db.insert_many(events)
        print(f"Ingested {n}/{len(records)} events")
        return

    if args.cmd == "report":
        with EventDatabase(args.db, base_dir=base_dir) as db:
            evs = db.search(
                severity=args.severity,
                min_severity=args.min_severity,
                since=args.since,
                until=args.until,
                limit=args.limit,
            )
        rg = ReportGenerator(base_dir=base_dir)
        path = rg.generate(evs, args.out, title=args.title, include_raw=args.include_raw)
        print(f"Report written: {path}")
        return

    if args.cmd == "retention":
        with EventDatabase(args.db, base_dir=base_dir) as db:
            res = db.apply_retention(
                max_age_days=args.max_age_days,
                max_events=args.max_events,
                vacuum=args.vacuum,
            )
        print(res)
        return


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSanitize(unittest.TestCase):
    def test_strips_control(self):
        self.assertEqual(sanitize_text("a\x00b\x07c"), "abc")

    def test_truncates(self):
        s = sanitize_text("x" * 100, max_len=10)
        self.assertTrue(s.startswith("x" * 10))
        self.assertIn("truncated", s)

    def test_none(self):
        self.assertEqual(sanitize_text(None), "")


class TestValidation(unittest.TestCase):
    def test_missing_rule(self):
        with self.assertRaises(ValidationError):
            DetectionEvent.from_mapping(
                {"severity": "high", "timestamp": "2024-01-01T00:00:00Z"}
            )

    def test_bad_severity(self):
        with self.assertRaises(ValidationError):
            DetectionEvent.from_mapping({
                "rule_id": "r", "rule_name": "n",
                "severity": "bogus", "timestamp": "2024-01-01T00:00:00Z",
            })

    def test_bad_timestamp(self):
        with self.assertRaises(ValidationError):
            DetectionEvent.from_mapping({
                "rule_id": "r", "rule_name": "n",
                "severity": "low", "timestamp": "not a date",
            })

    def test_alias_fields(self):
        e = DetectionEvent.from_mapping({
            "id": "r1", "name": "Test", "risk_level": "high",
            "time": "2024-01-01T00:00:00Z",
            "pid": 123, "cmdline": "evil.exe -x",
        })
        self.assertEqual(e.rule_id, "r1")
        self.assertEqual(e.rule_name, "Test")
        self.assertEqual(e.severity, "high")
        self.assertEqual(e.process_pid, 123)
        self.assertEqual(e.process_cmdline, "evil.exe -x")

    def test_reject_bad_object(self):
        with self.assertRaises(ValidationError):
            DetectionEvent.from_mapping(42)

    def test_negative_pid(self):
        with self.assertRaises(ValidationError):
            DetectionEvent.from_mapping({
                "rule_id": "r", "rule_name": "n",
                "severity": "low", "timestamp": "2024-01-01T00:00:00Z",
                "pid": -1,
            })


class TestPathSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_ok(self):
        p = safe_path(self.tmp, "out.pdf", allowed_extensions={".pdf"})
        self.assertTrue(p.startswith(os.path.realpath(self.tmp)))

    def test_absolute(self):
        with self.assertRaises(SecurityError):
            safe_path(self.tmp, "/etc/passwd")

    def test_traversal(self):
        with self.assertRaises(SecurityError):
            safe_path(self.tmp, "../evil.pdf", allowed_extensions={".pdf"})

    def test_bad_ext(self):
        with self.assertRaises(SecurityError):
            safe_path(self.tmp, "out.exe", allowed_extensions={".pdf"})

    def test_nul(self):
        with self.assertRaises(SecurityError):
            safe_path(self.tmp, "a\x00b.pdf", allowed_extensions={".pdf"})


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db = EventDatabase("events.db", base_dir=self.tmp, create_base=True)
        self.db.connect()

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _mk(self, **kw):
        base = {
            "event_id": str(uuid.uuid4()),
            "timestamp": _now_utc_iso(),
            "rule_id": "r1",
            "rule_name": "Rule One",
            "severity": "medium",
        }
        base.update(kw)
        return DetectionEvent.from_mapping(base)

    def test_insert_and_search(self):
        e1 = self._mk(severity="high", host="h1")
        e2 = self._mk(severity="low", host="h2")
        self.assertEqual(self.db.insert_many([e1, e2]), 2)
        self.assertEqual(self.db.count(), 2)
        high = self.db.search(severity="high")
        self.assertEqual(len(high), 1)
        self.assertEqual(high[0].event_id, e1.event_id)

    def test_duplicate_ignored(self):
        e = self._mk()
        self.db.insert_many([e])
        self.db.insert_many([e])
        self.assertEqual(self.db.count(), 1)

    def test_retention_max_events(self):
        for i in range(5):
            self.db.insert_many([self._mk(event_id=f"e{i}")])
        res = self.db.apply_retention(max_events=2)
        self.assertEqual(self.db.count(), 2)
        self.assertEqual(res["remaining"], 2)

    def test_retention_age(self):
        old = self._mk(timestamp="2000-01-01T00:00:00Z")
        new = self._mk()
        self.db.insert_many([old, new])
        self.db.apply_retention(max_age_days=30)
        self.assertEqual(self.db.count(), 1)

    def test_min_severity(self):
        self.db.insert_many([self._mk(severity="low"), self._mk(severity="critical")])
        got = self.db.search(min_severity="high")
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].severity, "critical")

    def test_text_search(self):
        self.db.insert_many([self._mk(description="evil thing")])
        self.assertEqual(len(self.db.search(text="evil")), 1)
        self.assertEqual(len(self.db.search(text="good")), 0)

    def test_migrations_idempotent(self):
        self.db.close()
        self.db = EventDatabase("events.db", base_dir=self.tmp, create_base=True)
        self.db.connect()
        rows = self.db.conn.execute("SELECT version FROM schema_version ORDER BY version").fetchall()
        versions = [r[0] for r in rows]
        self.assertEqual(versions, [v for v, _ in MIGRATIONS])


class TestReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_generate_pdf(self):
        rg = ReportGenerator(base_dir=self.tmp)
        path = rg.generate(
            make_sample_events(), "report.pdf",
            title="Test Report", subtitle="Unit test", include_raw=True,
        )
        self.assertTrue(os.path.exists(path))
        self.assertGreater(os.path.getsize(path), 1000)
        with open(path, "rb") as f:
            self.assertEqual(f.read(4), b"%PDF")

    def test_untrusted_text(self):
        rg = ReportGenerator(base_dir=self.tmp)
        ev = DetectionEvent.from_mapping({
            "rule_id": "r",
            "rule_name": "<script>alert(1)</script>",
            "severity": "high",
            "timestamp": _now_utc_iso(),
            "description": "x < y & z > w",
        })
        path = rg.generate([ev], "unsafe.pdf")
        self.assertTrue(os.path.exists(path))

    def test_bad_extension(self):
        rg = ReportGenerator(base_dir=self.tmp)
        with self.assertRaises(SecurityError):
            rg.generate([], "x.txt")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if "--test" in sys.argv:
        sys.argv.remove("--test")
        unittest.main()
    else:
        _cli()
