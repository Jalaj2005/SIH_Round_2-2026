"""Local, offline IoC database (SQLite, stdlib only). Swap for LMDB/RocksDB by keeping get/bulk_add/count."""
from __future__ import annotations
import sqlite3
import threading

KINDS = ("ip", "domain", "ja3", "ja4")


class IoCStore:
    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("""CREATE TABLE IF NOT EXISTS iocs(
            kind TEXT NOT NULL, value TEXT NOT NULL, category TEXT, confidence REAL DEFAULT 0.9, source TEXT,
            PRIMARY KEY(kind, value)) WITHOUT ROWID""")
        self._lock = threading.Lock()

    def get(self, kind: str, value: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT category, confidence, source FROM iocs WHERE kind=? AND value=?",
                                   (kind, value)).fetchone()
        return {"kind": kind, "value": value, "category": row[0], "confidence": row[1], "source": row[2]} if row else None

    def bulk_add(self, rows) -> int:
        """rows: iterable of (kind, value, category, confidence, source). Returns rows written."""
        clean = [(k, v.strip().lower(), c, float(conf), s) for k, v, c, conf, s in rows if k in KINDS and v.strip()]
        with self._lock:
            self._db.executemany("INSERT OR REPLACE INTO iocs VALUES(?,?,?,?,?)", clean)
            self._db.commit()
        return len(clean)

    def count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
