"""Elasticsearch storage for scanner-lite IP docs and ASN batches."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from threat_intel.elasticsearch.client import ElasticsearchClient

IP_INDEX_PREFIX = "scanner-ip-enrichment"
ASN_INDEX_PREFIX = "scanner-asn-batches"
IP_CACHE_INDEX = "scanner-ip-cache"
TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "es" / "templates"


class ScannerLiteStore:
    def __init__(self, client: Optional[ElasticsearchClient] = None):
        self.client = client or ElasticsearchClient()

    @staticmethod
    def _daily_index(prefix: str, date_str: Optional[str] = None) -> str:
        date_str = date_str or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return f"{prefix}-{date_str}"

    def ensure_templates(self) -> None:
        for name in ("scanner-ip-enrichment", "scanner-asn-batches", "stingar-enriched"):
            path = TEMPLATES_DIR / f"{name}.json"
            if path.exists():
                self.client.put_template(name, json.loads(path.read_text(encoding="utf-8")))

    def ping(self) -> bool:
        return self.client.ping()

    def get_ip_cache(self, ip_address: str) -> Optional[dict]:
        try:
            result = self.client.get_document(IP_CACHE_INDEX, ip_address)
            return result
        except RuntimeError:
            return None

    def count_ip_events_today(self, source_ip: str, *, batch_date: Optional[str] = None) -> int:
        """Count enrichment docs indexed today for ``source_ip`` (before current batch)."""
        index_name = self._daily_index(IP_INDEX_PREFIX, batch_date)
        try:
            result = self.client.request(
                "POST",
                f"{index_name}/_count",
                {"query": {"term": {"source_ip": source_ip}}},
            )
            return int(result.get("count", 0))
        except RuntimeError:
            return 0

    def index_ip_document(self, document: dict) -> dict:
        source_ip = document.get("source_ip", "")

        daily_index = self._daily_index(IP_INDEX_PREFIX)
        errors: list[str] = []
        indexed = 0

        for index_name in (daily_index, IP_CACHE_INDEX):
            try:
                cache_id = source_ip if index_name == IP_CACHE_INDEX else None
                self.client.index_document(index_name, document, cache_id)
                indexed += 1
            except RuntimeError as error:
                errors.append(f"{index_name}: {error}")

        return {"indexed": indexed, "errors": errors, "index": daily_index}

    def index_asn_batches(self, batches: list[dict]) -> dict:
        if not batches:
            return {"indexed": 0, "errors": []}

        date_str = batches[0].get("batch_date") or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        index_name = self._daily_index(ASN_INDEX_PREFIX, date_str)
        indexed = 0
        errors: list[str] = []

        for batch in batches:
            doc_id = f"{batch.get('batch_date')}_{batch.get('asn_number', 'AS0')}"
            try:
                self.client.index_document(index_name, batch, doc_id)
                indexed += 1
            except RuntimeError as error:
                errors.append(f"{doc_id}: {error}")

        return {"indexed": indexed, "errors": errors, "index": index_name}

    def search_asn_batches(self, batch_date: str) -> list[dict]:
        index_name = self._daily_index(ASN_INDEX_PREFIX, batch_date)
        try:
            result = self.client.search(
                index_name,
                {"query": {"match_all": {}}, "size": 100},
            )
        except RuntimeError:
            return []
        hits = result.get("hits", {}).get("hits", [])
        return [hit.get("_source", {}) for hit in hits]

    def stats(self) -> dict[str, Any]:
        return {
            "elasticsearch_reachable": self.ping(),
            "ip_index_prefix": IP_INDEX_PREFIX,
            "asn_index_prefix": ASN_INDEX_PREFIX,
        }
