"""Storage backend selection — Elasticsearch primary, SQLite fallback."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

from threat_intel.cache import IntelligenceCacheBackend, SQLiteIntelligenceCache


def storage_backend_name() -> str:
    return os.getenv("STINGAR_STORAGE_BACKEND", "elasticsearch").lower()


@lru_cache(maxsize=1)
def get_intelligence_cache() -> IntelligenceCacheBackend:
    backend = storage_backend_name()

    if backend == "sqlite":
        path = os.getenv(
            "STINGAR_LOCAL_CACHE_PATH",
            os.getenv("CENTRAL_CACHE_SQLITE_PATH", "data/local_cache.db"),
        )
        return SQLiteIntelligenceCache(db_path=path)

    if backend == "elasticsearch":
        from threat_intel.elasticsearch.intelligence_cache import ElasticsearchIntelligenceCache

        return ElasticsearchIntelligenceCache()

    if backend == "redis":
        from threat_intel.cache import RedisIntelligenceCache

        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        return RedisIntelligenceCache(redis_url=redis_url)

    raise ValueError(
        f"Unknown STINGAR_STORAGE_BACKEND '{backend}'. Use elasticsearch, sqlite, or redis."
    )


@lru_cache(maxsize=1)
def get_document_store():
    if storage_backend_name() != "elasticsearch":
        return None

    from threat_intel.elasticsearch.document_store import ElasticsearchDocumentStore

    return ElasticsearchDocumentStore()


def elasticsearch_available() -> bool:
    if storage_backend_name() != "elasticsearch":
        return False
    from threat_intel.elasticsearch.client import ElasticsearchClient

    return ElasticsearchClient().ping()
