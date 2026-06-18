"""Elasticsearch-backed IP intelligence summary cache (intel-summaries object index)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from threat_intel.cache import IntelligenceCacheBackend
from threat_intel.elasticsearch.client import ElasticsearchClient
from threat_intel.elasticsearch.schema import (
    ENRICHED_ILM_POLICY_NAME,
    ENRICHED_TEMPLATE_NAME,
    SUMMARIES_INDEX,
    SUMMARIES_TEMPLATE_NAME,
    enriched_ilm_policy,
    enriched_index_template,
    summaries_index_template,
)


class ElasticsearchIntelligenceCache(IntelligenceCacheBackend):
    """Primary intelligence cache on ES — content-addressed upserts by client_id + IP."""

    def __init__(self, client: Optional[ElasticsearchClient] = None):
        self.client = client or ElasticsearchClient()
        self._bootstrapped = False

    def ensure_bootstrap(self) -> None:
        if self._bootstrapped:
            return
        self.client.put_ilm_policy(ENRICHED_ILM_POLICY_NAME, enriched_ilm_policy())
        self.client.put_template(ENRICHED_TEMPLATE_NAME, enriched_index_template())
        self.client.put_template(SUMMARIES_TEMPLATE_NAME, summaries_index_template())
        self._bootstrapped = True

    @staticmethod
    def _doc_id(client_id: str, ip_address: str) -> str:
        return f"{client_id}:{ip_address}"

    def get(self, client_id: str, ip_address: str) -> Optional[dict]:
        self.ensure_bootstrap()
        doc = self.client.get_document(SUMMARIES_INDEX, self._doc_id(client_id, ip_address))
        if not doc:
            return None
        return doc.get("summary")

    def set(self, client_id: str, ip_address: str, summary: dict) -> None:
        self.ensure_bootstrap()
        now = datetime.now(timezone.utc).isoformat()
        self.client.index_document(
            SUMMARIES_INDEX,
            {
                "client_id": client_id,
                "ip_address": ip_address,
                "summary": summary,
                "enriched_at": now,
                "updated_at": now,
            },
            doc_id=self._doc_id(client_id, ip_address),
        )

    def filter_new_ips(self, client_id: str, ip_addresses: list[str]) -> list[str]:
        self.ensure_bootstrap()
        unique_ips = sorted({ip for ip in ip_addresses if ip})
        if not unique_ips:
            return []

        doc_ids = [self._doc_id(client_id, ip) for ip in unique_ips]
        found = self.client.mget_documents(SUMMARIES_INDEX, doc_ids)
        cached = {doc_id.split(":", 1)[1] for doc_id in found if ":" in doc_id}
        return [ip for ip in unique_ips if ip not in cached]

    def stats(self) -> dict:
        self.ensure_bootstrap()
        try:
            result = self.client.search(
                SUMMARIES_INDEX,
                {"size": 0, "track_total_hits": True, "aggs": {"clients": {"cardinality": {"field": "client_id"}}}},
            )
            total = result.get("hits", {}).get("total", {})
            if isinstance(total, dict):
                total_count = total.get("value", 0)
            else:
                total_count = total
            client_count = result.get("aggregations", {}).get("clients", {}).get("value", 0)
        except RuntimeError:
            total_count = 0
            client_count = 0

        return {
            "backend": "elasticsearch",
            "index": SUMMARIES_INDEX,
            "total_entries": total_count,
            "client_count": client_count,
            "cluster_url": self.client.base_url,
        }
