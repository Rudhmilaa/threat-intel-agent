"""Central enrichment orchestration used by the enrichment server."""

from __future__ import annotations

from typing import Optional

from threat_intel.cache import IntelligenceCacheBackend, get_cache_backend
from threat_intel.protocols import summarize_enrichment_stats
from threat_intel.scanners import ScannerRegistry, configure_scanners


def _import_core():
    import main as core

    return core


def _extract_source_ips(events: list[dict]) -> list[str]:
    return sorted({event.get("source_ip") for event in events if event.get("source_ip")})


def enrich_events_for_client(
    events: list[dict],
    client_id: str,
    new_ips: Optional[list[str]] = None,
    intelligence_cache: Optional[dict] = None,
    cache_backend: Optional[IntelligenceCacheBackend] = None,
    auto_detect_new_ips: bool = False,
) -> dict:
    """
    Run the full central enrichment pipeline for a STINGAR event batch.

    Uses the client's merged scanner table and only performs fresh IP enrichment
    for addresses listed in `new_ips`. Other IPs reuse persistent cache entries.

    When `auto_detect_new_ips=True`, central determines new IPs from the cache
    backend instead of trusting the client-provided `new_ips` list.
    """
    core = _import_core()
    registry = ScannerRegistry.for_client(client_id)
    configure_scanners(registry)

    backend = cache_backend or get_cache_backend()
    source_ips = _extract_source_ips(events)

    if auto_detect_new_ips:
        new_ip_set = set(backend.filter_new_ips(client_id, source_ips))
    else:
        new_ip_set = set(new_ips or [])

    enriched_documents = []
    central_new_enrichments = 0
    central_cache_hits = 0
    new_summaries: dict[str, dict] = {}

    for event in events:
        source_ip = event.get("source_ip")
        if not source_ip:
            continue

        summary = backend.get(client_id, source_ip)

        if summary is None or source_ip in new_ip_set:
            summary = core.build_intelligence_summary(source_ip)
            backend.set(client_id, source_ip, summary)
            new_summaries[source_ip] = summary
            cache_status = "miss"
            central_new_enrichments += 1
        else:
            cache_status = "hit"
            central_cache_hits += 1

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
        "enrichment_stats": summarize_enrichment_stats(
            events=events,
            new_ips=sorted(new_ip_set),
            central_new_enrichments=central_new_enrichments,
            central_cache_hits=central_cache_hits,
        ),
        "cache_stats": backend.stats(),
    }


def enrich_ip_for_client(
    ip_address: str,
    client_id: str,
    cache_backend: Optional[IntelligenceCacheBackend] = None,
) -> dict:
    core = _import_core()
    registry = ScannerRegistry.for_client(client_id)
    configure_scanners(registry)

    backend = cache_backend or get_cache_backend()
    cached = backend.get(client_id, ip_address)
    if cached is not None:
        return cached

    summary = core.build_intelligence_summary(ip_address)
    backend.set(client_id, ip_address, summary)
    return summary


def enrich_ips_for_client(
    ip_addresses: list[str],
    client_id: str,
    cache_backend: Optional[IntelligenceCacheBackend] = None,
) -> dict:
    backend = cache_backend or get_cache_backend()
    summaries = {}

    for ip_address in ip_addresses:
        summaries[ip_address] = enrich_ip_for_client(
            ip_address,
            client_id,
            cache_backend=backend,
        )

    return {
        "client_id": client_id,
        "summaries": summaries,
        "cache_stats": backend.stats(),
    }
