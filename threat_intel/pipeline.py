"""Central enrichment orchestration used by the enrichment server."""

from __future__ import annotations

from typing import Optional

from threat_intel.cache import IntelligenceCacheBackend, get_cache_backend
from threat_intel.enrichment_core import enrich_events_batch, enrich_ip


def enrich_events_for_client(
    events: list[dict],
    client_id: str,
    new_ips: Optional[list[str]] = None,
    intelligence_cache: Optional[dict] = None,
    cache_backend: Optional[IntelligenceCacheBackend] = None,
    auto_detect_new_ips: bool = False,
    policy_context: Optional[dict] = None,
) -> dict:
    return enrich_events_batch(
        events=events,
        client_id=client_id,
        cache_backend=cache_backend or get_cache_backend(),
        new_ips=new_ips,
        auto_detect_new_ips=auto_detect_new_ips,
        policy_context=policy_context or {"client_id": client_id},
        pipeline_label="threat_intelligence_enrichment",
    )


def enrich_ip_for_client(
    ip_address: str,
    client_id: str,
    cache_backend: Optional[IntelligenceCacheBackend] = None,
) -> dict:
    return enrich_ip(
        ip_address,
        client_id,
        cache_backend=cache_backend or get_cache_backend(),
        policy_context={"client_id": client_id},
    )


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
