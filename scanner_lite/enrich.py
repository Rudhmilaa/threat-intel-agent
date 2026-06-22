"""Main enrichment orchestration."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from threat_intel.scanners import ScannerRegistry, configure_scanners

from scanner_lite.asn import build_asn_batches, resolve_asn
from scanner_lite.cascade import run_cascade
from scanner_lite.classifier import build_scanner_tag
from scanner_lite.storage.es_store import ScannerLiteStore


def _normalize_event(event: dict) -> dict:
    return {
        "source_ip": event.get("source_ip"),
        "destination_ip": event.get("destination_ip"),
        "destination_port": event.get("destination_port"),
        "attack_type": event.get("attack_type", "unknown"),
        "protocol": event.get("protocol"),
        "honeypot_type": event.get("honeypot_type"),
        "sensor_id": event.get("sensor_id"),
    }


def enrich_ip(
    ip_address: str,
    *,
    client_id: str = "scanner-lite",
    event: Optional[dict] = None,
    store: Optional[ScannerLiteStore] = None,
) -> dict:
    configure_scanners(ScannerRegistry.for_client(client_id))

    es_store = store or ScannerLiteStore()
    if not event:
        cached = es_store.get_ip_cache(ip_address)
        if cached:
            return cached

    cascade_result = run_cascade(ip_address)
    signals = cascade_result["signals"]
    scanner_tag = build_scanner_tag(signals.get("scanner_tag") or {})
    asn = resolve_asn(ip_address, signals)
    outcome = cascade_result["outcome"]

    document = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": ip_address,
        "outcome_category": outcome["outcome_category"],
        "outcome_confidence": outcome["confidence"],
        "outcome_reasons": outcome["reasons"],
        "scanner_tag": scanner_tag,
        "asn": asn,
        "api_call_trace": cascade_result["api_call_trace"],
        "signals_summary": {
            k: _brief(v) for k, v in signals.items() if k != "scanner_tag"
        },
    }

    if event:
        normalized = _normalize_event(event)
        document.update(
            {
                "destination_ip": normalized.get("destination_ip"),
                "destination_port": normalized.get("destination_port"),
                "attack_type": normalized.get("attack_type"),
                "protocol": normalized.get("protocol"),
                "honeypot_type": normalized.get("honeypot_type"),
                "sensor_id": normalized.get("sensor_id"),
            }
        )

    es_store.index_ip_document(document)
    return document


def enrich_events(
    events: list[dict],
    *,
    client_id: str = "scanner-lite",
    store: Optional[ScannerLiteStore] = None,
) -> dict[str, Any]:
    configure_scanners(ScannerRegistry.for_client(client_id))
    es_store = store or ScannerLiteStore()

    enriched: list[dict] = []
    for event in events:
        source_ip = event.get("source_ip")
        if not source_ip:
            continue
        doc = enrich_ip(source_ip, client_id=client_id, event=event, store=es_store)
        enriched.append(doc)

    asn_batches = build_asn_batches(enriched)
    batch_stats = es_store.index_asn_batches(asn_batches)

    category_counts: dict[str, int] = {}
    total_api_calls = 0
    for doc in enriched:
        cat = doc.get("outcome_category", "unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1
        total_api_calls += len(doc.get("api_call_trace", []))

    return {
        "enriched_count": len(enriched),
        "enriched_documents": enriched,
        "category_counts": category_counts,
        "total_api_calls": total_api_calls,
        "asn_batches": asn_batches,
        "es_stats": batch_stats,
    }


def _brief(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: value[k] for k in list(value.keys())[:6]}
    return value
