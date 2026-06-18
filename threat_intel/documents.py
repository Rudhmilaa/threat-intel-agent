"""Elasticsearch document conversion."""

from __future__ import annotations

from datetime import datetime, timezone


def convert_to_elastic_document(
    honeypot_event: dict,
    intelligence_summary: dict
) -> dict:
    """
    Converts a STINGAR honeypot event + enrichment output
    into an Elasticsearch-ready document.
    """

    severity = intelligence_summary.get("severity", {})
    investigation = intelligence_summary.get("investigation", {})
    campaign = intelligence_summary.get("campaign", {})
    threat_actor = intelligence_summary.get("threat_actor", {})

    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),

        "event": {
            "source": "stingar_honeypot",
            "type": "honeypot_attack",
            "original": honeypot_event,
        },

        "source": {
            "ip": honeypot_event.get("source_ip"),
            "port": honeypot_event.get("source_port"),
        },

        "destination": {
            "ip": honeypot_event.get("destination_ip"),
            "port": honeypot_event.get("destination_port"),
        },

        "network": {
            "protocol": honeypot_event.get("protocol"),
            "transport": honeypot_event.get("transport", "tcp"),
        },

        "stingar": {
            "sensor_id": honeypot_event.get("sensor_id"),
            "honeypot_type": honeypot_event.get("honeypot_type"),
            "attack_type": honeypot_event.get("attack_type"),
        },

        "threat": {
            "indicator": {
                "ip": intelligence_summary.get("indicator"),
                "type": "ip_address",
            },
            "severity": severity.get("severity"),
            "threat_score": severity.get("threat_score"),
            "confidence_score": severity.get("confidence_score"),
            "risk_factors": severity.get("risk_factors", []),
        },

        "investigation": {
            "classification": investigation.get("investigation_classification"),
            "category": investigation.get("category"),
            "priority": investigation.get("priority"),
            "reasons": investigation.get("reasons", []),
        },

        "campaign": {
            "name": campaign.get("campaign_name"),
            "type": campaign.get("campaign_type"),
            "confidence": campaign.get("campaign_confidence"),
            "priority": campaign.get("priority"),
            "malware_families": campaign.get("malware_families", []),
            "related_ips": campaign.get("related_ips", []),
            "related_domains": campaign.get("related_domains", []),
            "related_hashes": campaign.get("related_hashes", []),
        },

        "threat_actor": {
            "name": threat_actor.get("threat_actor"),
            "confidence": threat_actor.get("attribution_confidence"),
            "motivation": threat_actor.get("motivation"),
        },

        "elastic_metadata": {
            "document_type": "stingar_enriched_honeypot_event",
            "pipeline": "threat_intelligence_enrichment",
            "version": "1.0",
        },
    }
