"""Shared deterministic enrichment orchestration for local and central pipelines."""

from __future__ import annotations

from typing import Any, Optional

from threat_intel.cache import IntelligenceCacheBackend, get_cache_backend
from threat_intel.documents import convert_to_elastic_document
from threat_intel.incidents import (
    build_incident_clusters,
    prioritize_incidents,
    summarize_enriched_batch,
)
from threat_intel.intelligence_summary import build_intelligence_summary as _build_summary
from threat_intel.protocols import summarize_enrichment_stats
from threat_intel.scanners import ScannerRegistry, configure_scanners


def configure_client(client_id: str) -> None:
    registry = ScannerRegistry.for_client(client_id)
    configure_scanners(registry)


def _extract_source_ips(events: list[dict]) -> list[str]:
    return sorted({event.get("source_ip") for event in events if event.get("source_ip")})


def build_intelligence_summary(
    ip_address: str,
    client_id: Optional[str] = None,
    policy_context: Optional[dict] = None,
) -> dict:
    if client_id:
        configure_client(client_id)

    summary = _build_summary(ip_address)

    if policy_context:
        from threat_intel.policy_engine import apply_policy_to_summary

        summary = apply_policy_to_summary(
            summary,
            ip_address,
            client_id=client_id or policy_context.get("client_id"),
            direction=policy_context.get("direction", "inbound"),
        )

    return summary


def enrich_events_batch(
    events: list[dict],
    client_id: str,
    cache_backend: Optional[IntelligenceCacheBackend] = None,
    new_ips: Optional[list[str]] = None,
    auto_detect_new_ips: bool = False,
    policy_context: Optional[dict] = None,
    pipeline_label: str = "threat_intelligence_enrichment",
) -> dict:
    configure_client(client_id)
    backend = cache_backend or get_cache_backend()
    source_ips = _extract_source_ips(events)

    if auto_detect_new_ips:
        new_ip_set = set(backend.filter_new_ips(client_id, source_ips))
    else:
        new_ip_set = set(new_ips or [])

    enriched_documents = []
    central_new_enrichments = 0
    central_cache_hits = 0
    ctx = {"client_id": client_id, **(policy_context or {})}

    for event in events:
        source_ip = event.get("source_ip")
        if not source_ip:
            continue

        summary = backend.get(client_id, source_ip)

        if summary is None or source_ip in new_ip_set:
            summary = build_intelligence_summary(
                source_ip,
                client_id=client_id,
                policy_context=ctx,
            )
            backend.set(client_id, source_ip, summary)
            cache_status = "miss"
            central_new_enrichments += 1
        else:
            cache_status = "hit"
            central_cache_hits += 1

        elastic_doc = convert_to_elastic_document(event, summary)
        elastic_doc["elastic_metadata"]["cache_status"] = cache_status
        elastic_doc["elastic_metadata"]["cache_key"] = source_ip
        elastic_doc["elastic_metadata"]["client_id"] = client_id
        elastic_doc["elastic_metadata"]["pipeline"] = pipeline_label

        if client_id:
            from threat_intel.policy_engine import annotate_document_policy
            from threat_intel.taxonomy import build_document_taxonomy

            elastic_doc = annotate_document_policy(elastic_doc, client_id)
            doc_taxonomy = build_document_taxonomy(elastic_doc)
            existing_tags = elastic_doc.get("taxonomy", {}).get("tags", [])
            doc_taxonomy["tags"] = list(dict.fromkeys(existing_tags + doc_taxonomy["tags"]))
            elastic_doc["taxonomy"] = doc_taxonomy

        enriched_documents.append(elastic_doc)

    incident_clusters = build_incident_clusters(enriched_documents)
    prioritized_incidents = prioritize_incidents(incident_clusters)

    es_stats = None
    from threat_intel.storage import get_document_store

    document_store = get_document_store()
    if document_store is not None and enriched_documents:
        from threat_intel.policy_engine import sanitize_document
        from threat_intel.sharing_policy import load_sharing_policy

        policy = load_sharing_policy(client_id)
        docs_for_es = [sanitize_document(doc, policy) for doc in enriched_documents]
        es_stats = document_store.index_documents(docs_for_es)

    return {
        "client_id": client_id,
        "enriched_documents": enriched_documents,
        "batch_summary": summarize_enriched_batch(enriched_documents),
        "incident_clusters": incident_clusters,
        "prioritized_incidents": prioritized_incidents,
        "enrichment_stats": summarize_enrichment_stats(
            events=events,
            new_ips=sorted(new_ip_set),
            central_new_enrichments=central_new_enrichments,
            central_cache_hits=central_cache_hits,
        ),
        "cache_stats": backend.stats(),
        "es_stats": es_stats,
        "storage_backend": backend.stats().get("backend"),
        "enrichment_source": "local" if pipeline_label == "local_enrichment" else "central",
    }


def enrich_ip(
    ip_address: str,
    client_id: str,
    cache_backend: Optional[IntelligenceCacheBackend] = None,
    policy_context: Optional[dict] = None,
) -> dict:
    configure_client(client_id)
    backend = cache_backend or get_cache_backend()
    cached = backend.get(client_id, ip_address)
    if cached is not None:
        return cached

    ctx = {"client_id": client_id, **(policy_context or {})}
    summary = build_intelligence_summary(ip_address, client_id=client_id, policy_context=ctx)
    backend.set(client_id, ip_address, summary)
    return summary
