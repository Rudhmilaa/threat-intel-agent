"""Local STINGAR enrichment pipeline — Elasticsearch primary store."""

from __future__ import annotations

from typing import Optional

from threat_intel.enrichment_core import enrich_events_batch, enrich_ip
from threat_intel.storage import get_intelligence_cache


def enrich_events_locally(
    events: list[dict],
    client_id: str,
    new_ips: Optional[list[str]] = None,
    auto_detect_new_ips: bool = True,
) -> dict:
    return enrich_events_batch(
        events=events,
        client_id=client_id,
        cache_backend=get_intelligence_cache(),
        new_ips=new_ips,
        auto_detect_new_ips=auto_detect_new_ips,
        policy_context={"client_id": client_id},
        pipeline_label="local_enrichment",
    )


def enrich_ip_locally(ip_address: str, client_id: str) -> dict:
    return enrich_ip(
        ip_address,
        client_id,
        cache_backend=get_intelligence_cache(),
        policy_context={"client_id": client_id},
    )
