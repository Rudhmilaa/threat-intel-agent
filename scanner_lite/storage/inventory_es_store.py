"""Elasticsearch durable store for scanner inventory ranges."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Optional

from threat_intel.elasticsearch.client import ElasticsearchClient

INVENTORY_INDEX_PREFIX = "scanner-inventory"


class ScannerInventoryEsStore:
    def __init__(self, client: Optional[ElasticsearchClient] = None):
        self.client = client or ElasticsearchClient()

    @staticmethod
    def _daily_index(date_str: Optional[str] = None) -> str:
        date_str = date_str or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return f"{INVENTORY_INDEX_PREFIX}-{date_str}"

    @staticmethod
    def _doc_id(inventory_version: int, vendor: str, cidr: str) -> str:
        raw = f"{inventory_version}:{vendor}:{cidr}"
        digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:24]
        return digest

    @staticmethod
    def _range_documents(publish_payload: dict[str, Any]) -> list[dict]:
        meta = publish_payload.get("meta") or {}
        version = int(meta.get("version", 0))
        refreshed_at = meta.get("refreshed_at") or datetime.now(timezone.utc).isoformat()
        feed_refreshed = {
            snap.get("vendor", ""): snap.get("refreshed_at")
            for snap in publish_payload.get("feed_snapshots", [])
        }
        docs: list[dict] = []

        for row in publish_payload.get("csv_rows", []):
            cidr = row.get("cidr")
            confidence = (row.get("confidence") or "").lower()
            if not cidr or confidence not in {"high", "medium"}:
                continue
            docs.append(
                {
                    "@timestamp": refreshed_at,
                    "inventory_version": version,
                    "vendor": row.get("vendor"),
                    "scanner_type": row.get("scanner_type"),
                    "cidr": cidr,
                    "confidence": confidence,
                    "source_url": row.get("source_url", ""),
                    "last_verified": row.get("last_verified", ""),
                    "source": "csv",
                }
            )

        for snap in publish_payload.get("feed_snapshots", []):
            vendor = snap.get("vendor", "")
            if not vendor:
                continue
            for cidr in snap.get("cidrs", []):
                docs.append(
                    {
                        "@timestamp": refreshed_at,
                        "inventory_version": version,
                        "vendor": vendor,
                        "scanner_type": snap.get("scanner_type", "internet_scanning"),
                        "cidr": cidr,
                        "confidence": (snap.get("confidence") or "medium").lower(),
                        "source_url": snap.get("source_url", ""),
                        "last_verified": snap.get("last_verified", ""),
                        "source": "feed_snapshot",
                        "feed_refreshed_at": feed_refreshed.get(vendor) or refreshed_at,
                    }
                )

        return docs

    def sync_from_publish(self, publish_payload: dict[str, Any]) -> dict[str, Any]:
        docs = self._range_documents(publish_payload)
        index_name = self._daily_index()
        indexed = 0
        errors: list[str] = []

        for doc in docs:
            doc_id = self._doc_id(doc["inventory_version"], doc["vendor"], doc["cidr"])
            try:
                self.client.index_document(index_name, doc, doc_id)
                indexed += 1
            except RuntimeError as error:
                errors.append(str(error))

        return {
            "indexed": indexed,
            "failed": len(docs) - indexed,
            "index": index_name,
            "inventory_version": (publish_payload.get("meta") or {}).get("version"),
            "errors": errors[:10],
        }

    def count_ranges(self, inventory_version: Optional[int] = None) -> int:
        index_name = self._daily_index()
        query: dict[str, Any] = {"query": {"match_all": {}}}
        if inventory_version is not None:
            query = {"query": {"term": {"inventory_version": inventory_version}}}
        try:
            result = self.client.request("POST", f"{index_name}/_count", query)
            return int(result.get("count", 0))
        except RuntimeError:
            return 0

    def search_by_vendor(self, vendor: str, size: int = 20) -> list[dict]:
        index_name = self._daily_index()
        body = {
            "size": size,
            "query": {"term": {"vendor": vendor}},
            "sort": [{"cidr": "asc"}],
        }
        try:
            result = self.client.search(index_name, body)
        except RuntimeError:
            return []
        hits = result.get("hits", {}).get("hits", [])
        return [hit.get("_source", {}) for hit in hits]

    def stats(self) -> dict[str, Any]:
        return {
            "elasticsearch_reachable": self.client.ping(),
            "index_prefix": INVENTORY_INDEX_PREFIX,
            "today_index": self._daily_index(),
            "today_doc_count": self.count_ranges(),
        }
