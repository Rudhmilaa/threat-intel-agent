"""Central threat intelligence enrichment server."""

from __future__ import annotations

import os
from typing import Any, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from central.auth import require_api_key
from central.llm_gateway import investigate_with_llm
from threat_intel.cache import get_cache_backend
from threat_intel.pipeline import enrich_events_for_client, enrich_ip_for_client, enrich_ips_for_client
from threat_intel.policy_engine import build_client_policy_summary, evaluate_shareability
from threat_intel.protocols import (
    build_enrich_ip_response,
    build_scanner_table_response,
    validate_honeypot_event,
)
from threat_intel.safelist import SafelistRegistry
from threat_intel.scanners import ScannerRegistry, configure_scanners, list_scanner_inventory
from threat_intel.scanner_inventory_maintenance import refresh_scanner_inventory
from threat_intel.sharing_policy import load_sharing_policy, save_sharing_policy
from threat_intel.storage import elasticsearch_available, get_document_store, storage_backend_name
from threat_intel.webhook_events import extract_events

load_dotenv()

app = FastAPI(
    title="Threat Intelligence Central Enrichment Server",
    description=(
        "Receives STINGAR honeypot events and new IP addresses from remote clients, "
        "runs enrichment/scoring/classification, and returns Elasticsearch-ready documents."
    ),
    version="1.2.0",
)


class EnrichEventsRequest(BaseModel):
    client_id: str = Field(..., description="Unique STINGAR deployment identifier")
    sensor_id: Optional[str] = Field(None, description="Sensor submitting the batch")
    events: list[dict] = Field(..., description="STINGAR honeypot events")
    new_ips: list[str] = Field(
        default_factory=list,
        description="IPs seen for the first time on the STINGAR client; central will enrich these fresh",
    )


class EnrichIpRequest(BaseModel):
    client_id: str
    ip_address: str


class EnrichIpsRequest(BaseModel):
    client_id: str
    ip_addresses: list[str]


class ScannerEntryRequest(BaseModel):
    client_id: str
    scanner: dict


class SafelistEntryRequest(BaseModel):
    client_id: str
    entry: dict


class SyncEventsRequest(BaseModel):
    client_id: str
    sensor_id: Optional[str] = None
    enriched_documents: list[dict] = Field(default_factory=list)
    batch_summary: Optional[dict] = None
    incident_clusters: Optional[list] = None
    prioritized_incidents: Optional[list] = None
    enrichment_stats: Optional[dict] = None
    enrichment_source: str = "local"


class LlmInvestigateRequest(BaseModel):
    client_id: str
    ioc: str
    ioc_type: str


class ClientPolicyUpdateRequest(BaseModel):
    deployment_mode: Optional[str] = None
    global_joined: Optional[bool] = None
    share_events: Optional[bool] = None
    share_enriched_documents: Optional[bool] = None
    share_mode: Optional[str] = None
    never_share_fields: Optional[list[str]] = None
    never_share_if_tags: Optional[list[str]] = None
    never_share_classifications: Optional[list[str]] = None
    never_share_destination_cidrs: Optional[list[str]] = None


@app.get("/health")
def health():
    cache = get_cache_backend()
    payload = {
        "status": "ok",
        "service": "central-enrichment-server",
        "storage_backend": storage_backend_name(),
        "cache": cache.stats(),
    }
    document_store = get_document_store()
    if document_store is not None:
        payload["elasticsearch"] = {
            "reachable": elasticsearch_available(),
            **document_store.stats(),
        }
    return payload


@app.get("/api/v1/cache/stats", dependencies=[Depends(require_api_key)])
def cache_stats():
    return get_cache_backend().stats()


@app.post("/api/v1/enrich/events", dependencies=[Depends(require_api_key)])
def enrich_events(request: EnrichEventsRequest):
    validation_errors = []
    for index, event in enumerate(request.events):
        errors = validate_honeypot_event(event)
        for error in errors:
            validation_errors.append(f"events[{index}]: {error}")

    if validation_errors:
        raise HTTPException(status_code=400, detail=validation_errors)

    return enrich_events_for_client(
        events=request.events,
        client_id=request.client_id,
        new_ips=request.new_ips,
        cache_backend=get_cache_backend(),
    )


@app.post("/api/v1/enrich/ip", dependencies=[Depends(require_api_key)])
def enrich_ip(request: EnrichIpRequest):
    summary = enrich_ip_for_client(
        request.ip_address,
        request.client_id,
        cache_backend=get_cache_backend(),
    )
    return build_enrich_ip_response(request.client_id, request.ip_address, summary)


@app.post("/api/v1/enrich/ips", dependencies=[Depends(require_api_key)])
def enrich_ips(request: EnrichIpsRequest):
    return enrich_ips_for_client(
        request.ip_addresses,
        request.client_id,
        cache_backend=get_cache_backend(),
    )


def _process_stingar_webhook(client_id: str, payload: dict[str, Any]) -> dict:
    events = extract_events(payload, default_sensor_id=payload.get("sensor_id"))
    if not events:
        raise HTTPException(status_code=400, detail="No events found in webhook payload.")

    validation_errors = []
    for index, event in enumerate(events):
        errors = validate_honeypot_event(event)
        for error in errors:
            validation_errors.append(f"events[{index}]: {error}")

    if validation_errors:
        raise HTTPException(status_code=400, detail=validation_errors)

    result = enrich_events_for_client(
        events=events,
        client_id=client_id,
        cache_backend=get_cache_backend(),
        auto_detect_new_ips=True,
    )
    result["webhook"] = {
        "received_events": len(events),
        "auto_detected_new_ips": result["enrichment_stats"]["new_ips_submitted"],
    }
    return result


@app.post("/api/v1/webhooks/stingar", dependencies=[Depends(require_api_key)])
async def stingar_webhook(request: Request):
    """
    STINGAR push endpoint.

    Configure your honeypot/STINGAR deployment to POST events here. Central will
    auto-detect new source IPs using the persistent cache and enrich only those.
    """
    payload: dict[str, Any] = await request.json()
    client_id = payload.get("client_id")
    if not client_id:
        raise HTTPException(status_code=400, detail="Missing required field: client_id")

    return _process_stingar_webhook(client_id, payload)


@app.post("/api/v1/webhooks/stingar/{client_id}", dependencies=[Depends(require_api_key)])
async def stingar_webhook_for_client(client_id: str, request: Request):
    payload: dict[str, Any] = await request.json()
    payload["client_id"] = client_id
    return _process_stingar_webhook(client_id, payload)


@app.get("/api/v1/scanners", dependencies=[Depends(require_api_key)])
def list_scanners(client_id: Optional[str] = None):
    registry = ScannerRegistry.for_client(client_id)
    return {
        "client_id": client_id,
        "scanners": registry.list_scanners(),
    }


@app.get("/api/v1/scanners/table", dependencies=[Depends(require_api_key)])
def scanner_table(client_id: Optional[str] = None):
    registry = ScannerRegistry.for_client(client_id)
    return build_scanner_table_response(client_id, registry.scanner_table())


@app.get("/api/v1/scanners/inventory", dependencies=[Depends(require_api_key)])
def scanner_inventory(client_id: Optional[str] = None):
    if client_id:
        configure_scanners(ScannerRegistry.for_client(client_id))
    return list_scanner_inventory()


@app.post("/api/v1/scanners/refresh", dependencies=[Depends(require_api_key)])
def refresh_scanners(dry_run: bool = False):
    report = refresh_scanner_inventory(write_changes=not dry_run, reload_registry=not dry_run)
    payload = report.to_dict()
    if report.errors and not dry_run:
        payload["status"] = "completed_with_errors"
    elif dry_run:
        payload["status"] = "dry_run"
    else:
        payload["status"] = "ok"
    return payload


@app.post("/api/v1/scanners", dependencies=[Depends(require_api_key)])
def add_client_scanner(request: ScannerEntryRequest):
    registry = ScannerRegistry.for_client(request.client_id)
    try:
        created = registry.add_client_scanner(request.scanner, persist=True)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    return {"client_id": request.client_id, "scanner": created}


@app.delete("/api/v1/scanners/{scanner_id}", dependencies=[Depends(require_api_key)])
def remove_client_scanner(scanner_id: str, client_id: str):
    registry = ScannerRegistry.for_client(client_id)
    removed = registry.remove_client_scanner(scanner_id, persist=True)
    if not removed:
        raise HTTPException(
            status_code=404,
            detail="Scanner not found or not a client-owned scanner entry.",
        )
    return {"client_id": client_id, "removed_scanner_id": scanner_id}


@app.get("/api/v1/safelist", dependencies=[Depends(require_api_key)])
def list_safelist(client_id: Optional[str] = None):
    registry = SafelistRegistry.for_client(client_id)
    return {"client_id": client_id, "entries": registry.list_entries()}


@app.get("/api/v1/safelist/table", dependencies=[Depends(require_api_key)])
def safelist_table(client_id: Optional[str] = None):
    registry = SafelistRegistry.for_client(client_id)
    return {
        "client_id": client_id,
        "entry_count": len(registry.list_entries()),
        "range_count": len(registry.table()),
        "table": registry.table(),
    }


@app.post("/api/v1/safelist", dependencies=[Depends(require_api_key)])
def add_safelist_entry(request: SafelistEntryRequest):
    registry = SafelistRegistry.for_client(request.client_id)
    try:
        created = registry.add_client_entry(request.entry, persist=True)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return {"client_id": request.client_id, "entry": created}


@app.delete("/api/v1/safelist/{entry_id}", dependencies=[Depends(require_api_key)])
def remove_safelist_entry(entry_id: str, client_id: str):
    registry = SafelistRegistry.for_client(client_id)
    removed = registry.remove_client_entry(entry_id, persist=True)
    if not removed:
        raise HTTPException(
            status_code=404,
            detail="Safelist entry not found or not a client-owned entry.",
        )
    return {"client_id": client_id, "removed_entry_id": entry_id}


@app.post("/api/v1/sync/events", dependencies=[Depends(require_api_key)])
def sync_events(request: SyncEventsRequest):
    backend = get_cache_backend()
    document_store = get_document_store()
    merged = 0
    rejected = 0
    rejection_reasons: list[dict] = []
    accepted_documents: list[dict] = []

    for document in request.enriched_documents:
        decision = evaluate_shareability(document, request.client_id)
        if not decision["allowed"]:
            rejected += 1
            rejection_reasons.append(
                {
                    "source_ip": document.get("source", {}).get("ip"),
                    "reason": decision["reason"],
                }
            )
            continue

        sanitized = decision["sanitized_document"]
        if not sanitized:
            rejected += 1
            rejection_reasons.append(
                {
                    "source_ip": document.get("source", {}).get("ip"),
                    "reason": "sanitized document missing after policy check",
                }
            )
            continue

        accepted_documents.append(sanitized)
        source_ip = sanitized.get("source", {}).get("ip")
        if not source_ip:
            continue

        summary = {
            "indicator": source_ip,
            "severity": {
                "severity": sanitized.get("threat", {}).get("severity"),
                "threat_score": sanitized.get("threat", {}).get("threat_score"),
                "confidence_score": sanitized.get("threat", {}).get("confidence_score"),
                "risk_factors": sanitized.get("threat", {}).get("risk_factors", []),
            },
            "investigation": {
                "investigation_classification": sanitized.get("investigation", {}).get("classification"),
                "category": sanitized.get("investigation", {}).get("category"),
                "priority": sanitized.get("investigation", {}).get("priority"),
                "reasons": sanitized.get("investigation", {}).get("reasons", []),
            },
            "campaign": sanitized.get("campaign", {}),
            "threat_actor": sanitized.get("threat_actor", {}),
        }
        backend.set(request.client_id, source_ip, summary)
        merged += 1

    es_stats = None
    if document_store is not None and accepted_documents:
        es_stats = document_store.index_documents(accepted_documents)

    if rejected and not merged:
        raise HTTPException(
            status_code=403,
            detail={
                "message": "All documents rejected by central sharing policy validation",
                "rejected": rejected,
                "reasons": rejection_reasons[:20],
            },
        )

    return {
        "client_id": request.client_id,
        "sync_status": "accepted" if merged else "rejected",
        "documents_received": len(request.enriched_documents),
        "documents_accepted": len(accepted_documents),
        "documents_rejected": rejected,
        "rejection_reasons": rejection_reasons[:20],
        "summaries_merged": merged,
        "enrichment_source": request.enrichment_source,
        "cache_stats": backend.stats(),
        "es_stats": es_stats,
        "batch_summary": request.batch_summary,
        "incident_clusters": request.incident_clusters,
        "prioritized_incidents": request.prioritized_incidents,
        "enrichment_stats": request.enrichment_stats,
    }


@app.post("/api/v1/llm/investigate", dependencies=[Depends(require_api_key)])
def llm_investigate(request: LlmInvestigateRequest):
    return investigate_with_llm(request.client_id, request.ioc, request.ioc_type)


@app.get("/api/v1/clients/{client_id}/policy", dependencies=[Depends(require_api_key)])
def get_client_policy(client_id: str):
    return build_client_policy_summary(client_id)


@app.put("/api/v1/clients/{client_id}/policy", dependencies=[Depends(require_api_key)])
def update_client_policy(client_id: str, request: ClientPolicyUpdateRequest):
    updates = {
        key: value
        for key, value in request.model_dump().items()
        if value is not None
    }
    policy = save_sharing_policy(client_id, updates)
    return build_client_policy_summary(client_id) | {"updated_policy": policy}


@app.get("/api/v1/sessions", dependencies=[Depends(require_api_key)])
def search_sessions(
    q: str = "",
    client_id: Optional[str] = None,
    hours: int = 24,
    size: int = 50,
):
    document_store = get_document_store()
    if document_store is None:
        raise HTTPException(
            status_code=503,
            detail="Session search requires STINGAR_STORAGE_BACKEND=elasticsearch.",
        )
    try:
        return document_store.search_sessions(
            q,
            client_id=client_id,
            hours=hours,
            size=size,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


def main():
    import uvicorn

    host = os.getenv("CENTRAL_HOST", "0.0.0.0")
    port = int(os.getenv("CENTRAL_PORT", "8080"))
    uvicorn.run("central.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
