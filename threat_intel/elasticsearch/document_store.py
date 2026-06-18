"""Write enriched honeypot sessions to stingar-enriched-* daily indices."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Optional

from threat_intel.elasticsearch.client import ElasticsearchClient
from threat_intel.elasticsearch.schema import ENRICHED_INDEX_PREFIX


class ElasticsearchDocumentStore:
    """Primary document store for enriched STINGAR sessions/events."""

    def __init__(self, client: Optional[ElasticsearchClient] = None):
        self.client = client or ElasticsearchClient()

    @staticmethod
    def _daily_index(timestamp: Optional[str] = None) -> str:
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                dt = datetime.now(timezone.utc)
        else:
            dt = datetime.now(timezone.utc)
        return f"{ENRICHED_INDEX_PREFIX}-{dt.strftime('%Y-%m-%d')}"

    @staticmethod
    def _document_id(document: dict) -> str:
        session_id = (
            document.get("session_id")
            or document.get("stingar", {}).get("session_id")
            or document.get("event", {}).get("original", {}).get("session_id")
        )
        if session_id:
            return str(session_id)

        fingerprint = "|".join(
            [
                document.get("@timestamp", ""),
                document.get("source", {}).get("ip", ""),
                str(document.get("destination", {}).get("port", "")),
                document.get("stingar", {}).get("attack_type", ""),
            ]
        )
        return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def prepare_document(document: dict) -> dict:
        """Denormalize query-friendly fields for the session query language."""
        prepared = dict(document)
        source_ip = document.get("source", {}).get("ip")
        if source_ip:
            prepared["src_ip"] = source_ip

        severity = (document.get("threat") or {}).get("severity", "INFORMATIONAL")
        prepared["effective_severity"] = str(severity).upper()

        taxonomy_tags = (document.get("taxonomy") or {}).get("tags", [])
        signals = [tag.split(":", 1)[1] for tag in taxonomy_tags if tag.startswith("signal:")]
        investigation = (document.get("investigation") or {}).get("classification")
        if investigation:
            signals.append(investigation)
        prepared["effective_signals"] = sorted(set(signals + taxonomy_tags))

        enrichment = prepared.setdefault("hp_data", {}).setdefault("enrichment", {})
        enrichment.setdefault("effective_severity", prepared["effective_severity"])
        enrichment.setdefault("effective_signals", prepared["effective_signals"])
        enrichment.setdefault("version", "enriched-1")

        return prepared

    def index_documents(self, documents: list[dict]) -> dict[str, Any]:
        indexed = 0
        errors: list[str] = []
        indices: set[str] = set()

        for document in documents:
            prepared = self.prepare_document(document)
            index = self._daily_index(prepared.get("@timestamp"))
            doc_id = self._document_id(prepared)
            try:
                self.client.index_document(index, prepared, doc_id=doc_id)
                indexed += 1
                indices.add(index)
            except RuntimeError as error:
                errors.append(str(error))

        return {
            "indexed": indexed,
            "failed": len(errors),
            "indices": sorted(indices),
            "errors": errors[:5],
        }

    def search_sessions(
        self,
        query: str = "",
        *,
        client_id: Optional[str] = None,
        hours: int = 24,
        size: int = 50,
    ) -> dict:
        from threat_intel.elasticsearch.session_query import session_query_to_es

        body = session_query_to_es(query, client_id=client_id, hours=hours)
        body["size"] = size
        index_pattern = f"{ENRICHED_INDEX_PREFIX}-*"
        result = self.client.search(index_pattern, body)

        hits = []
        for hit in result.get("hits", {}).get("hits", []):
            source = hit.get("_source", {})
            hits.append(
                {
                    "id": hit.get("_id"),
                    "index": hit.get("_index"),
                    "timestamp": source.get("@timestamp"),
                    "src_ip": source.get("src_ip") or source.get("source", {}).get("ip"),
                    "severity": source.get("effective_severity"),
                    "signals": source.get("effective_signals", []),
                    "honeypot_type": source.get("stingar", {}).get("honeypot_type"),
                    "attack_type": source.get("stingar", {}).get("attack_type"),
                    "classification": source.get("investigation", {}).get("classification"),
                    "document": source,
                }
            )

        total = result.get("hits", {}).get("total", {})
        if isinstance(total, dict):
            total_count = total.get("value", 0)
        else:
            total_count = total

        return {
            "query": query,
            "hours": hours,
            "client_id": client_id,
            "total": total_count,
            "sessions": hits,
        }

    def stats(self) -> dict:
        try:
            result = self.client.search(
                f"{ENRICHED_INDEX_PREFIX}-*",
                {"size": 0, "track_total_hits": True},
            )
            total = result.get("hits", {}).get("total", {})
            if isinstance(total, dict):
                total_count = total.get("value", 0)
            else:
                total_count = total
        except RuntimeError:
            total_count = 0

        return {
            "backend": "elasticsearch",
            "index_pattern": f"{ENRICHED_INDEX_PREFIX}-*",
            "total_documents": total_count,
            "cluster_url": self.client.base_url,
        }
