"""SQLite-backed cache for advisories, malicious-package mirror, and scan results."""

from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


class Cache:
    """Thin SQLite wrapper. We avoid sqlite-utils' migration magic to keep things obvious."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self._migrate()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Cache:
        return self

    def __exit__(self, *_) -> None:
        self.close()

    @contextmanager
    def tx(self):
        try:
            yield self.conn
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    # ---- schema ----------------------------------------------------------------

    def _migrate(self) -> None:
        c = self.conn
        c.execute(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        version = self._meta("schema_version")
        if version is None:
            self._set_meta("schema_version", str(SCHEMA_VERSION))

        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS advisories (
                id TEXT PRIMARY KEY,
                ecosystem TEXT NOT NULL,
                name TEXT NOT NULL,
                summary TEXT,
                severity TEXT,
                affected_json TEXT,
                references_json TEXT,
                fetched_at INTEGER NOT NULL,
                raw_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_advisories_pkg
                ON advisories(ecosystem, name);

            CREATE TABLE IF NOT EXISTS malicious_packages (
                id TEXT PRIMARY KEY,
                ecosystem TEXT NOT NULL,
                name TEXT NOT NULL,
                summary TEXT,
                published TEXT,
                modified TEXT,
                source TEXT,
                raw_json TEXT,
                indexed_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_malicious_pkg
                ON malicious_packages(ecosystem, name);

            CREATE TABLE IF NOT EXISTS query_cache (
                cache_key TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL,
                fetched_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS hash_lookups (
                sha256 TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                verdict TEXT,
                detail_json TEXT,
                fetched_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at INTEGER NOT NULL,
                finished_at INTEGER,
                ecosystems TEXT,
                package_count INTEGER,
                finding_count INTEGER,
                payload_json TEXT
            );
            """
        )
        c.commit()

    # ---- meta helpers ----------------------------------------------------------

    def _meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else None

    def _set_meta(self, key: str, value: str) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    # ---- advisories ------------------------------------------------------------

    def upsert_advisory(
        self,
        advisory_id: str,
        ecosystem: str,
        name: str,
        summary: str | None,
        severity: str | None,
        affected: Any,
        references: Any,
        raw: Any,
    ) -> None:
        with self.tx() as c:
            c.execute(
                """
                INSERT INTO advisories(id, ecosystem, name, summary, severity,
                                       affected_json, references_json, fetched_at, raw_json)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    ecosystem=excluded.ecosystem,
                    name=excluded.name,
                    summary=excluded.summary,
                    severity=excluded.severity,
                    affected_json=excluded.affected_json,
                    references_json=excluded.references_json,
                    fetched_at=excluded.fetched_at,
                    raw_json=excluded.raw_json
                """,
                (
                    advisory_id,
                    ecosystem,
                    name.lower(),
                    summary,
                    severity,
                    json.dumps(affected) if affected is not None else None,
                    json.dumps(references) if references is not None else None,
                    int(time.time()),
                    json.dumps(raw) if raw is not None else None,
                ),
            )

    def advisories_for(self, ecosystem: str, name: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM advisories WHERE ecosystem=? AND name=?",
            (ecosystem, name.lower()),
        ).fetchall()
        return [dict(r) for r in rows]

    # ---- malicious packages ----------------------------------------------------

    def upsert_malicious(
        self,
        advisory_id: str,
        ecosystem: str,
        name: str,
        summary: str | None,
        published: str | None,
        modified: str | None,
        source: str | None,
        raw: Any,
    ) -> None:
        with self.tx() as c:
            c.execute(
                """
                INSERT INTO malicious_packages(id, ecosystem, name, summary,
                                               published, modified, source,
                                               raw_json, indexed_at)
                VALUES(?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                    ecosystem=excluded.ecosystem,
                    name=excluded.name,
                    summary=excluded.summary,
                    published=excluded.published,
                    modified=excluded.modified,
                    source=excluded.source,
                    raw_json=excluded.raw_json,
                    indexed_at=excluded.indexed_at
                """,
                (
                    advisory_id,
                    ecosystem,
                    name.lower(),
                    summary,
                    published,
                    modified,
                    source,
                    json.dumps(raw) if raw is not None else None,
                    int(time.time()),
                ),
            )

    def malicious_for(self, ecosystem: str, name: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM malicious_packages WHERE ecosystem=? AND name=?",
            (ecosystem, name.lower()),
        ).fetchall()
        return [dict(r) for r in rows]

    def malicious_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS n FROM malicious_packages").fetchone()
        return int(row["n"])

    def reset_malicious(self) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM malicious_packages")

    # ---- query cache (generic) -------------------------------------------------

    def get_query(self, cache_key: str, max_age_seconds: int) -> Any | None:
        row = self.conn.execute(
            "SELECT payload_json, fetched_at FROM query_cache WHERE cache_key=?",
            (cache_key,),
        ).fetchone()
        if not row:
            return None
        if int(time.time()) - row["fetched_at"] > max_age_seconds:
            return None
        try:
            return json.loads(row["payload_json"])
        except json.JSONDecodeError:
            return None

    def put_query(self, cache_key: str, payload: Any) -> None:
        with self.tx() as c:
            c.execute(
                """
                INSERT INTO query_cache(cache_key, payload_json, fetched_at)
                VALUES(?,?,?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    payload_json=excluded.payload_json,
                    fetched_at=excluded.fetched_at
                """,
                (cache_key, json.dumps(payload), int(time.time())),
            )

    # ---- hash lookups ----------------------------------------------------------

    def get_hash(self, sha256: str, max_age_seconds: int) -> dict[str, Any] | None:
        row = self.conn.execute(
            "SELECT * FROM hash_lookups WHERE sha256=?", (sha256,)
        ).fetchone()
        if not row:
            return None
        if int(time.time()) - row["fetched_at"] > max_age_seconds:
            return None
        return dict(row)

    def put_hash(self, sha256: str, source: str, verdict: str, detail: Any) -> None:
        with self.tx() as c:
            c.execute(
                """
                INSERT INTO hash_lookups(sha256, source, verdict, detail_json, fetched_at)
                VALUES(?,?,?,?,?)
                ON CONFLICT(sha256) DO UPDATE SET
                    source=excluded.source,
                    verdict=excluded.verdict,
                    detail_json=excluded.detail_json,
                    fetched_at=excluded.fetched_at
                """,
                (sha256, source, verdict, json.dumps(detail) if detail else None, int(time.time())),
            )

    # ---- scan runs -------------------------------------------------------------

    def record_scan(
        self,
        ecosystems: list[str],
        package_count: int,
        finding_count: int,
        payload: Any,
        started_at: int,
    ) -> int:
        with self.tx() as c:
            cur = c.execute(
                """
                INSERT INTO scan_runs(started_at, finished_at, ecosystems,
                                      package_count, finding_count, payload_json)
                VALUES(?,?,?,?,?,?)
                """,
                (
                    started_at,
                    int(time.time()),
                    ",".join(ecosystems),
                    package_count,
                    finding_count,
                    json.dumps(payload),
                ),
            )
            return int(cur.lastrowid or 0)
