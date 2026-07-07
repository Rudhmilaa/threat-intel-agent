"""Map scanner-lite enrichment documents to stingar-enriched session records."""

from __future__ import annotations

from typing import Any, Optional

OUTCOME_SEVERITY = {
    "malicious": "HIGH",
    "suspicious": "MEDIUM",
    "benign": "LOW",
    "unknown": "INFORMATIONAL",
}


def _raw_event(event: Optional[dict]) -> dict:
    if not event:
        return {}
    return event.get("original") or event


def _taxonomy_tags(enriched: dict, meta: dict) -> list[str]:
    tags: list[str] = []
    outcome = enriched.get("outcome_category", "unknown")
    tags.append(f"outcome:{outcome}")

    for behavior in meta.get("behavior_tags") or []:
        tags.append(f"behavior:{behavior}")

    scanner_tag = enriched.get("scanner_tag") or {}
    if scanner_tag.get("scanner_id"):
        tags.append(f"scanner:{scanner_tag['scanner_id']}")
    elif scanner_tag.get("vendor"):
        tags.append(f"scanner:{scanner_tag['vendor']}")

    attribution = meta.get("scanner_attribution")
    if attribution and attribution != "none":
        tags.append(f"attribution:{attribution}")

    freq = meta.get("frequency_tier")
    if freq and freq != "normal":
        tags.append(f"frequency:{freq}")

    return sorted(set(tags))


def build_outcome_summary(
    enriched: dict,
    meta: dict,
    scanner_tag: Optional[dict],
) -> dict[str, Any]:
    """Compact hover/drilldown payload for Attack Analysis session rows."""
    summary: dict[str, Any] = {
        "confidence": enriched.get("outcome_confidence"),
        "priority": meta.get("priority"),
        "classification": meta.get("investigation_classification"),
        "scanner_attribution": meta.get("scanner_attribution"),
        "frequency_tier": meta.get("frequency_tier"),
        "events_today": meta.get("events_today"),
        "behavior_tags": list(meta.get("behavior_tags") or []),
        "reasons": list(enriched.get("outcome_reasons") or []),
    }
    if scanner_tag:
        summary["scanner_vendor"] = scanner_tag.get("vendor")
        summary["scanner_id"] = scanner_tag.get("scanner_id")
        summary["matched_cidr"] = scanner_tag.get("matched_cidr")
    if meta.get("scanner_inventory_version") is not None:
        summary["inventory_version"] = meta["scanner_inventory_version"]
    return summary


def to_stingar_session(
    enriched: dict,
    event: Optional[dict] = None,
    *,
    client_id: str = "scanner-lite",
) -> dict:
    """Convert a scanner-lite enrichment doc into a stingar-enriched session document."""
    meta = enriched.get("investigation_metadata") or {}
    outcome = enriched.get("outcome_category", "unknown")
    severity = OUTCOME_SEVERITY.get(outcome, "INFORMATIONAL")
    raw = _raw_event(event)
    behavior_tags = meta.get("behavior_tags") or []
    scanner_tag = enriched.get("scanner_tag")
    taxonomy_tags = _taxonomy_tags(enriched, meta)

    source_ip = enriched.get("source_ip")
    source_port = raw.get("srcPort") or raw.get("source_port") or event.get("source_port") if event else None
    session_id = raw.get("session_id") or raw.get("sessionId")

    source: dict[str, Any] = {"ip": source_ip}
    if source_port is not None:
        source["port"] = source_port

    destination: dict[str, Any] = {}
    if enriched.get("destination_ip"):
        destination["ip"] = enriched.get("destination_ip")
    if enriched.get("destination_port") is not None:
        destination["port"] = enriched.get("destination_port")

    asn = enriched.get("asn") or {}
    if asn.get("country"):
        source["geo"] = {"country_code": asn["country"]}

    trace = enriched.get("api_call_trace") or []
    scanner_lite_block: dict[str, Any] = {
        "outcome_category": outcome,
        "outcome_confidence": enriched.get("outcome_confidence"),
        "scanner_attribution": meta.get("scanner_attribution"),
        "frequency_tier": meta.get("frequency_tier"),
        "events_today": meta.get("events_today"),
        "events_in_batch": meta.get("events_in_batch"),
        "behavior_tags": behavior_tags,
        "api_calls": len(trace),
    }
    if scanner_tag:
        scanner_lite_block["scanner_vendor"] = scanner_tag.get("vendor")
        scanner_lite_block["scanner_id"] = scanner_tag.get("scanner_id")
        scanner_lite_block["matched_cidr"] = scanner_tag.get("matched_cidr")

    if meta.get("scanner_inventory_version") is not None:
        scanner_lite_block["inventory_version"] = meta["scanner_inventory_version"]
    if meta.get("scanner_inventory_refreshed_at"):
        scanner_lite_block["inventory_refreshed_at"] = meta["scanner_inventory_refreshed_at"]

    ts = enriched.get("@timestamp")
    honeypot_type = enriched.get("honeypot_type") or raw.get("app") or (event or {}).get("honeypot_type")
    protocol = enriched.get("protocol") or raw.get("protocol") or (event or {}).get("protocol")

    doc = {
        "@timestamp": ts,
        "start_time": ts,
        "app": honeypot_type,
        "protocol": protocol,
        "src_ip": source_ip,
        "outcome_category": outcome,
        "outcome_summary": build_outcome_summary(enriched, meta, scanner_tag),
        "source": source,
        "destination": destination,
        "network": {
            "protocol": enriched.get("protocol"),
            "transport": raw.get("transport") or (event or {}).get("transport") or "tcp",
        },
        "stingar": {
            "sensor_id": enriched.get("sensor_id"),
            "honeypot_type": enriched.get("honeypot_type"),
            "attack_type": enriched.get("attack_type"),
        },
        "threat": {
            "indicator": {"ip": source_ip, "type": "ip_address"},
            "severity": severity,
            "confidence_score": enriched.get("outcome_confidence"),
            "risk_factors": list(enriched.get("outcome_reasons") or []),
        },
        "investigation": {
            "classification": meta.get("investigation_classification"),
            "category": outcome,
            "priority": meta.get("priority"),
            "reasons": list(enriched.get("outcome_reasons") or []),
        },
        "taxonomy": {"tags": taxonomy_tags},
        "hp_data": {
            "enrichment": {
                "version": "scanner-lite-1",
                "effective_severity": severity,
                "effective_signals": sorted(set(taxonomy_tags + behavior_tags)),
                "scanner_lite": scanner_lite_block,
            }
        },
        "elastic_metadata": {
            "document_type": "stingar_enriched_honeypot_event",
            "pipeline": "scanner-enrichment-lite",
            "client_id": client_id,
            "version": "1.0",
        },
        "event": {
            "source": "stingar_honeypot",
            "type": "honeypot_attack",
            "original": raw or event,
        },
    }
    if session_id:
        sid = str(session_id)
        doc["session_id"] = sid
        doc["stingar"]["session_id"] = sid
    return doc
