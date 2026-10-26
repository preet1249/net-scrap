"""SQLite persistence (stdlib sqlite3, WAL). Events are immutable (INSERT OR IGNORE); derived tables can be rebuilt."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterator, Sequence

from ..models import NetworkEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, seq INTEGER NOT NULL, ts REAL NOT NULL, source TEXT NOT NULL,
  target_id TEXT, session_id TEXT, request_id TEXT, event_type TEXT NOT NULL, raw_json TEXT NOT NULL,
  schema_version TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS ix_events_seq ON events(seq);
CREATE INDEX IF NOT EXISTS ix_events_req ON events(session_id, request_id);
CREATE TABLE IF NOT EXISTS requests (record_id TEXT PRIMARY KEY, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pages (page_id TEXT PRIMARY KEY, json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings (finding_id TEXT PRIMARY KEY, json TEXT NOT NULL);
"""


class SqliteEventStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self.count = 0

    # ---- events -----------------------------------------------------------------------------
    def append_events(self, events: Sequence[NetworkEvent]) -> None:
        rows = [(e.event_id, e.scan_id, e.seq, e.timestamp, e.source, e.target_id, e.session_id, e.request_id,
                 e.event_type, json.dumps(e.raw_event, separators=(",", ":")), e.schema_version) for e in events]
        with self._lock:
            c = self._conn
            c.execute("BEGIN")
            try:
                c.executemany("INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)
                c.execute("INSERT OR REPLACE INTO meta VALUES ('heartbeat', ?)", (str(time.time()),))
                c.execute("COMMIT")
            except Exception:
                c.execute("ROLLBACK")
                raise
        self.count += len(rows)

    def iter_events(self) -> Iterator[NetworkEvent]:
        """Stream events in capture order using a separate read connection (safe while a writer is active)."""
        conn = sqlite3.connect(f"file:{self.path.as_posix()}?mode=ro", uri=True)
        try:
            cur = conn.execute("SELECT event_id, scan_id, seq, ts, source, target_id, session_id, request_id, event_type, "
                               "raw_json, schema_version FROM events ORDER BY seq")
            for r in cur:
                yield NetworkEvent(event_id=r[0], scan_id=r[1], seq=r[2], timestamp=r[3], source=r[4], target_id=r[5],
                                   session_id=r[6], request_id=r[7], event_type=r[8], raw_event=json.loads(r[9]),
                                   schema_version=r[10])
        finally:
            conn.close()

    def event_count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # ---- meta / derived ---------------------------------------------------------------------
    def set_meta(self, key: str, value: Any) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, json.dumps(value, default=str)))

    def get_meta(self, key: str, default: Any = None) -> Any:
        with self._lock:
            r = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(r[0]) if r else default

    def replace_table(self, table: str, id_col: str, items: Sequence[tuple[str, str]]) -> None:
        assert table in ("requests", "pages", "findings")
        with self._lock:
            self._conn.execute("BEGIN")
            self._conn.execute(f"DELETE FROM {table}")
            self._conn.executemany(f"INSERT OR REPLACE INTO {table} ({id_col}, json) VALUES (?,?)", items)
            self._conn.execute("COMMIT")

    def upsert_page(self, page_id: str, js: str) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO pages VALUES (?,?)", (page_id, js))

    def load_json(self, table: str) -> list[dict[str, Any]]:
        assert table in ("requests", "pages", "findings")
        with self._lock:
            return [json.loads(r[0]) for r in self._conn.execute(f"SELECT json FROM {table} ORDER BY rowid")]

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                pass
            self._conn.close()
