"""HTTP payload schemas for STINGAR client <-> central enrichment server communication."""

from __future__ import annotations

from typing import Any, Optional


# ── STINGAR honeypot event (client -> central) ────────────────────────────────
#
# Required fields per event:
#   source_ip, destination_ip, destination_port, attack_type
#
# Optional but recommended:
#   source_port, protocol, transport, sensor_id, honeypot_type, @timestamp
#
HONEYPOT_EVENT_FIELDS = {
    "source_ip": "Attacker/source IP observed by honeypot",
    "source_port": "Source port of the connection",
    "destination_ip": "Honeypot destination IP",
    "destination_port": "Target service port (22, 443, 8080, etc.)",
    "protocol": "Application protocol label (ssh, http, telnet)",
    "transport": "Transport protocol (tcp, udp)",
    "sensor_id": "STINGAR sensor identifier",
    "honeypot_type": "Honeypot implementation (cowrie, web_honeypot, etc.)",
    "attack_type": "Normalized attack label (ssh_bruteforce, service_probe, etc.)",
}


def validate_honeypot_event(event: dict) -> list[str]:
    errors = []
    for field in ("source_ip", "destination_ip", "destination_port", "attack_type"):
        if not event.get(field):
            errors.append(f"Missing required field: {field}")
    return errors


# ── POST /api/v1/enrich/events ────────────────────────────────────────────────

def build_enrich_events_request(
    client_id: str,
    events: list[dict],
    sensor_id: Optional[str] = None,
    new_ips: Optional[list[str]] = None,
) -> dict:
    """
    Payload sent from a STINGAR server to the central enrichment server.

    The client tracks seen IPs locally. Only IPs listed in `new_ips` trigger
    fresh enrichment on the central side; all other IPs reuse central cache.
    """
    return {
        "client_id": client_id,
        "sensor_id": sensor_id,
        "events": events,
        "new_ips": new_ips or [],
    }


def build_enrich_ips_request(client_id: str, ip_addresses: list[str]) -> dict:
    """Payload for enriching a batch of new IPs only (no honeypot event context)."""
    return {
        "client_id": client_id,
        "ip_addresses": ip_addresses,
    }


# ── Central server response shapes ────────────────────────────────────────────

def build_enrich_events_response(
    client_id: str,
    enriched_documents: list[dict],
    batch_summary: dict,
    incident_clusters: list[dict],
    prioritized_incidents: list[dict],
    enrichment_stats: dict,
) -> dict:
    return {
        "client_id": client_id,
        "enriched_documents": enriched_documents,
        "batch_summary": batch_summary,
        "incident_clusters": incident_clusters,
        "prioritized_incidents": prioritized_incidents,
        "enrichment_stats": enrichment_stats,
    }


def build_enrich_ip_response(client_id: str, ip_address: str, intelligence_summary: dict) -> dict:
    return {
        "client_id": client_id,
        "ip_address": ip_address,
        "intelligence_summary": intelligence_summary,
    }


def build_scanner_table_response(client_id: Optional[str], registry_table: list[dict]) -> dict:
    return {
        "client_id": client_id,
        "scanner_count": len({row["scanner_id"] for row in registry_table}),
        "range_count": len(registry_table),
        "table": registry_table,
    }


def summarize_enrichment_stats(
    events: list[dict],
    new_ips: list[str],
    central_new_enrichments: int,
    central_cache_hits: int,
) -> dict[str, Any]:
    event_ips = [event.get("source_ip") for event in events if event.get("source_ip")]
    return {
        "total_events": len(events),
        "unique_source_ips": len(set(event_ips)),
        "new_ips_submitted": len(new_ips),
        "central_new_enrichments": central_new_enrichments,
        "central_cache_hits": central_cache_hits,
    }
