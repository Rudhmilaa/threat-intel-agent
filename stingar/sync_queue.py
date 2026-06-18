"""Persistent offline queue for syncing sanitized enrichment payloads to central."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class SyncQueue:
    def __init__(self, db_path: Path | str | None = None):
        self.db_path = Path(db_path or os.getenv("STINGAR_SYNC_QUEUE_PATH", "data/sync_queue.db"))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS sync_queue (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  client_id TEXT NOT NULL,
                  payload_json TEXT NOT NULL,
                  status TEXT NOT NULL DEFAULT 'pending',
                  attempts INTEGER NOT NULL DEFAULT 0,
                  last_error TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                )
                """
            )
            connection.commit()

    def enqueue(self, client_id: str, payload: dict) -> int:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO sync_queue (client_id, payload_json, status, created_at, updated_at)
                VALUES (?, ?, 'pending', ?, ?)
                """,
                (client_id, json.dumps(payload), now, now),
            )
            connection.commit()
            return int(cursor.lastrowid)

    def list_pending(self, limit: int = 50) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, client_id, payload_json, attempts, last_error, created_at
                FROM sync_queue
                WHERE status = 'pending'
                ORDER BY id ASC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            {
                "id": row["id"],
                "client_id": row["client_id"],
                "payload": json.loads(row["payload_json"]),
                "attempts": row["attempts"],
                "last_error": row["last_error"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def mark_sent(self, queue_id: int) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE sync_queue
                SET status = 'sent', updated_at = ?
                WHERE id = ?
                """,
                (now, queue_id),
            )
            connection.commit()

    def mark_failed(self, queue_id: int, error: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE sync_queue
                SET attempts = attempts + 1,
                    last_error = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (error, now, queue_id),
            )
            connection.commit()

    def stats(self) -> dict:
        with self._connect() as connection:
            pending = connection.execute(
                "SELECT COUNT(*) AS count FROM sync_queue WHERE status = 'pending'"
            ).fetchone()["count"]
            sent = connection.execute(
                "SELECT COUNT(*) AS count FROM sync_queue WHERE status = 'sent'"
            ).fetchone()["count"]

        return {
            "db_path": str(self.db_path),
            "pending": pending,
            "sent": sent,
        }
