"""STINGAR webhook ingest for scanner enrichment lite."""

from __future__ import annotations

from typing import Any, Optional

from scanner_lite.enrich import enrich_events
from scanner_lite.storage.es_store import ScannerLiteStore
from threat_intel.webhook_events import extract_raw_stingar_events


def process_stingar_payload(
    payload: dict | list,
    *,
    client_id: str = "scanner-lite",
    sensor_id: Optional[str] = None,
    store: Optional[ScannerLiteStore] = None,
) -> dict[str, Any]:
    """
    Accept the same webhook shapes as ``stingar/webhook_listener.py`` and enrich
    via the scanner-lite cascade (CSV-first, cost-aware API calls).
    """
    events = extract_raw_stingar_events(payload, default_sensor_id=sensor_id)
    if not events:
        raise ValueError("No events found in webhook payload.")

    result = enrich_events(events, client_id=client_id, store=store)
    return {
        "status": "accepted",
        "service": "scanner-enrichment-lite",
        "received_events": len(events),
        "enriched_count": result.get("enriched_count", 0),
        "category_counts": result.get("category_counts", {}),
        "total_api_calls": result.get("total_api_calls", 0),
        "es_stats": result.get("es_stats"),
        "enriched_documents": result.get("enriched_documents", []),
    }
