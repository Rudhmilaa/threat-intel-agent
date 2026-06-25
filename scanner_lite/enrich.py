"""Main enrichment orchestration."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Optional

from threat_intel.scanners import ScannerRegistry, configure_scanners

from scanner_lite.asn import build_asn_batches, resolve_asn
from scanner_lite.cascade import run_cascade
from scanner_lite.classifier import build_scanner_tag, classify_outcome
from scanner_lite.metadata import build_investigation_metadata, honeypot_signals_from_event
from scanner_lite.storage.es_store import ScannerLiteStore


def _normalize_event(event: dict) -> dict:
    raw = event.get("original") if event.get("original") else event
    source_ip = (
        event.get("source_ip")
        or raw.get("srcIp")
        or raw.get("src_ip")
        or event.get("srcIp")
        or event.get("src_ip")
    )
    destination_ip = (
        event.get("destination_ip")
        or raw.get("dstIp")
        or raw.get("dst_ip")
        or event.get("dstIp")
        or event.get("dst_ip")
    )
    destination_port = (
        event.get("destination_port")
        or raw.get("dstPort")
        or raw.get("dst_port")
        or event.get("dstPort")
        or event.get("dst_port")
    )
    hp = raw.get("hpData") or event.get("hpData") or {}
    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "attack_type": (
            event.get("attack_type")
            or hp.get("eventType")
            or "unknown"
        ),
        "protocol": event.get("protocol") or hp.get("protocol"),
        "honeypot_type": event.get("honeypot_type") or raw.get("app") or event.get("app"),
        "sensor_id": event.get("sensor_id") or raw.get("sensor_id"),
        "original": raw if (hp or "srcIp" in raw or "hpData" in raw) else None,
    }


def enrich_ip(
    ip_address: str,
    *,
    client_id: str = "scanner-lite",
    event: Optional[dict] = None,
    store: Optional[ScannerLiteStore] = None,
    events_for_ip: int = 1,
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

    hp_signals = honeypot_signals_from_event(event)
    if hp_signals:
        signals.update(hp_signals)
        outcome = classify_outcome(signals)
    else:
        outcome = cascade_result["outcome"]

    investigation_metadata = build_investigation_metadata(
        outcome=outcome,
        scanner_tag=scanner_tag,
        event=event,
        events_for_ip=events_for_ip,
    )

    asn = resolve_asn(ip_address, signals)

    document = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": ip_address,
        "outcome_category": outcome["outcome_category"],
        "outcome_confidence": outcome["confidence"],
        "outcome_reasons": outcome["reasons"],
        "investigation_metadata": investigation_metadata,
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

    ip_counts = Counter(
        (_normalize_event(e).get("source_ip") or e.get("source_ip"))
        for e in events
        if (_normalize_event(e).get("source_ip") or e.get("source_ip"))
    )

    enriched: list[dict] = []
    for event in events:
        normalized = _normalize_event(event)
        source_ip = normalized.get("source_ip") or event.get("source_ip")
        if not source_ip:
            continue
        doc = enrich_ip(
            source_ip,
            client_id=client_id,
            event=event,
            store=es_store,
            events_for_ip=ip_counts[source_ip],
        )
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
