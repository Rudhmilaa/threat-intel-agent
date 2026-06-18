"""Persistent intelligence cache backends for the central enrichment server."""

from __future__ import annotations

import json
import os
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SQLITE_PATH = PROJECT_ROOT / "data" / "central_cache.db"


class IntelligenceCacheBackend(ABC):
    @abstractmethod
    def get(self, client_id: str, ip_address: str) -> Optional[dict]:
        ...

    @abstractmethod
    def set(self, client_id: str, ip_address: str, summary: dict) -> None:
        ...

    @abstractmethod
    def filter_new_ips(self, client_id: str, ip_addresses: list[str]) -> list[str]:
        ...

    def get_many(self, client_id: str, ip_addresses: list[str]) -> dict[str, dict]:
        results = {}
        for ip_address in ip_addresses:
            summary = self.get(client_id, ip_address)
            if summary is not None:
                results[ip_address] = summary
        return results

    def set_many(self, client_id: str, entries: dict[str, dict]) -> None:
        for ip_address, summary in entries.items():
            self.set(client_id, ip_address, summary)


class SQLiteIntelligenceCache(IntelligenceCacheBackend):
    def __init__(self, db_path: Path | str = DEFAULT_SQLITE_PATH):
        self.db_path = Path(db_path)
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
                CREATE TABLE IF NOT EXISTS intelligence_cache (
                  client_id TEXT NOT NULL,
                  ip_address TEXT NOT NULL,
                  summary_json TEXT NOT NULL,
                  enriched_at TEXT NOT NULL,
                  PRIMARY KEY (client_id, ip_address)
                )
                """
            )
            connection.commit()

    def get(self, client_id: str, ip_address: str) -> Optional[dict]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT summary_json
                FROM intelligence_cache
                WHERE client_id = ? AND ip_address = ?
                """,
                (client_id, ip_address),
            ).fetchone()

        if not row:
            return None

        return json.loads(row["summary_json"])

    def set(self, client_id: str, ip_address: str, summary: dict) -> None:
        enriched_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO intelligence_cache (client_id, ip_address, summary_json, enriched_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(client_id, ip_address)
                DO UPDATE SET summary_json = excluded.summary_json, enriched_at = excluded.enriched_at
                """,
                (client_id, ip_address, json.dumps(summary), enriched_at),
            )
            connection.commit()

    def filter_new_ips(self, client_id: str, ip_addresses: list[str]) -> list[str]:
        unique_ips = sorted({ip for ip in ip_addresses if ip})
        if not unique_ips:
            return []

        placeholders = ", ".join("?" for _ in unique_ips)
        query = f"""
          SELECT ip_address
          FROM intelligence_cache
          WHERE client_id = ? AND ip_address IN ({placeholders})
        """

        with self._connect() as connection:
            rows = connection.execute(query, [client_id, *unique_ips]).fetchall()

        cached_ips = {row["ip_address"] for row in rows}
        return [ip for ip in unique_ips if ip not in cached_ips]

    def stats(self) -> dict:
        with self._connect() as connection:
            total = connection.execute(
                "SELECT COUNT(*) AS count FROM intelligence_cache"
            ).fetchone()["count"]
            clients = connection.execute(
                "SELECT COUNT(DISTINCT client_id) AS count FROM intelligence_cache"
              ).fetchone()["count"]

        return {
            "backend": "sqlite",
            "db_path": str(self.db_path),
            "total_entries": total,
            "client_count": clients,
        }


class RedisIntelligenceCache(IntelligenceCacheBackend):
    def __init__(self, redis_url: str, key_prefix: str = "intel"):
        try:
            import redis
        except ImportError as error:
            raise RuntimeError(
                "Redis cache backend requires the redis package. Install with: pip install redis"
            ) from error

        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.key_prefix = key_prefix

    def _key(self, client_id: str, ip_address: str) -> str:
        return f"{self.key_prefix}:{client_id}:{ip_address}"

    def get(self, client_id: str, ip_address: str) -> Optional[dict]:
        raw = self.redis.get(self._key(client_id, ip_address))
        if not raw:
            return None
        return json.loads(raw)

    def set(self, client_id: str, ip_address: str, summary: dict) -> None:
        self.redis.set(self._key(client_id, ip_address), json.dumps(summary))

    def filter_new_ips(self, client_id: str, ip_addresses: list[str]) -> list[str]:
        unique_ips = sorted({ip for ip in ip_addresses if ip})
        if not unique_ips:
            return []

        keys = [self._key(client_id, ip_address) for ip_address in unique_ips]
        values = self.redis.mget(keys)
        return [
            ip_address
            for ip_address, value in zip(unique_ips, values)
            if value is None
        ]

    def stats(self) -> dict:
        pattern = f"{self.key_prefix}:*"
        total = sum(1 for _ in self.redis.scan_iter(match=pattern, count=500))
        return {
            "backend": "redis",
            "key_prefix": self.key_prefix,
            "total_entries": total,
        }


_cache_instance: Optional[IntelligenceCacheBackend] = None


def create_cache_backend() -> IntelligenceCacheBackend:
    """Return the intelligence cache backend (ES primary when STINGAR_STORAGE_BACKEND=elasticsearch)."""
    from threat_intel.storage import get_intelligence_cache

    return get_intelligence_cache()


def get_cache_backend() -> IntelligenceCacheBackend:
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = create_cache_backend()
    return _cache_instance


def configure_cache_backend(backend: IntelligenceCacheBackend) -> None:
    global _cache_instance
    _cache_instance = backend
