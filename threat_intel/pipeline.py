"""Central enrichment orchestration used by the enrichment server."""

from __future__ import annotations

from typing import Optional

from threat_intel.protocols import summarize_enrichment_stats
from threat_intel.scanners import ScannerRegistry, configure_scanners


def _import_core():
    import main as core

    return core


def enrich_events_for_client(
    events: list[dict],
    client_id: str,
    new_ips: Optional[list[str]] = None,
    intelligence_cache: Optional[dict] = None,
) -> dict:
    """
    Run the full central enrichment pipeline for a STINGAR event batch.

    Uses the client's merged scanner table and only performs fresh IP enrichment
    for addresses listed in `new_ips`. Other IPs reuse `intelligence_cache`.
    """
    core = _import_core()
    registry = ScannerRegistry.for_client(client_id)
    configure_scanners(registry)

    cache = intelligence_cache if intelligence_cache is not None else {}
    new_ip_set = set(new_ips or [])
    enriched_documents = []
    central_new_enrichments = 0
    central_cache_hits = 0

    for event in events:
        source_ip = event.get("source_ip")
        if not source_ip:
            continue

        if source_ip not in cache or source_ip in new_ip_set:
            cache[source_ip] = core.build_intelligence_summary(source_ip)
            cache_status = "miss"
            central_new_enrichments += 1
        else:
            cache_status = "hit"
            central_cache_hits += 1

        summary = cache[source_ip]
        elastic_doc = core.convert_to_elastic_document(event, summary)
        elastic_doc["elastic_metadata"]["cache_status"] = cache_status
        elastic_doc["elastic_metadata"]["cache_key"] = source_ip
        elastic_doc["elastic_metadata"]["client_id"] = client_id
        enriched_documents.append(elastic_doc)

    batch_summary = core.summarize_enriched_batch(enriched_documents)
    incident_clusters = core.build_incident_clusters(enriched_documents)
    prioritized_incidents = core.prioritize_incidents(incident_clusters)

    return {
        "client_id": client_id,
        "enriched_documents": enriched_documents,
        "batch_summary": batch_summary,
        "incident_clusters": incident_clusters,
        "prioritized_incidents": prioritized_incidents,
        "intelligence_cache": cache,
        "enrichment_stats": summarize_enrichment_stats(
            events=events,
            new_ips=list(new_ip_set),
            central_new_enrichments=central_new_enrichments,
            central_cache_hits=central_cache_hits,
        ),
    }


def enrich_ip_for_client(ip_address: str, client_id: str) -> dict:
    core = _import_core()
    registry = ScannerRegistry.for_client(client_id)
    configure_scanners(registry)
    return core.build_intelligence_summary(ip_address)


def enrich_ips_for_client(ip_addresses: list[str], client_id: str) -> dict:
    summaries = {}
    for ip_address in ip_addresses:
        summaries[ip_address] = enrich_ip_for_client(ip_address, client_id)
    return {
        "client_id": client_id,
        "summaries": summaries,
    }
