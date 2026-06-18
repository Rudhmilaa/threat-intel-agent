"""Full intelligence summary builder."""

from __future__ import annotations

from threat_intel.campaign import attribute_threat_actor, build_campaign_profile
from threat_intel.investigation import classify_investigation_outcome_tool
from threat_intel.severity import calculate_enriched_severity_tool


def build_intelligence_summary(ip_address: str) -> dict:
    severity = calculate_enriched_severity_tool(ip_address)
    investigation = classify_investigation_outcome_tool(ip_address)
    campaign = build_campaign_profile(ip_address, "ip_address")
    actor = attribute_threat_actor(campaign)

    return {
        "indicator": ip_address,
        "severity": severity,
        "investigation": investigation,
        "campaign": campaign,
        "threat_actor": actor,
    }


def enrich_honeypot_events(events: list) -> list:
    from threat_intel.documents import convert_to_elastic_document

    enriched_documents = []
    for event in events:
        source_ip = event.get("source_ip")
        if not source_ip:
            continue
        summary = build_intelligence_summary(source_ip)
        enriched_documents.append(convert_to_elastic_document(event, summary))
    return enriched_documents


def enrich_honeypot_events_with_cache(events: list) -> list:
    from threat_intel.documents import convert_to_elastic_document

    enriched_documents = []
    intelligence_cache = {}
    for event in events:
        source_ip = event.get("source_ip")
        if not source_ip:
            continue
        if source_ip not in intelligence_cache:
            intelligence_cache[source_ip] = build_intelligence_summary(source_ip)
            cache_status = "miss"
        else:
            cache_status = "hit"
        summary = intelligence_cache[source_ip]
        elastic_doc = convert_to_elastic_document(event, summary)
        elastic_doc["elastic_metadata"]["cache_status"] = cache_status
        elastic_doc["elastic_metadata"]["cache_key"] = source_ip
        enriched_documents.append(elastic_doc)
    return enriched_documents
