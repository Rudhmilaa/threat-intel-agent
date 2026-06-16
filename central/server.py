"""Central threat intelligence enrichment server."""

from __future__ import annotations

import os
from typing import Any, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from central.auth import require_api_key
from threat_intel.cache import get_cache_backend
from threat_intel.pipeline import enrich_events_for_client, enrich_ip_for_client, enrich_ips_for_client
from threat_intel.protocols import (
    build_enrich_ip_response,
    build_scanner_table_response,
    validate_honeypot_event,
)
from threat_intel.scanners import ScannerRegistry
from threat_intel.webhook_events import extract_events

load_dotenv()

app = FastAPI(
    title="Threat Intelligence Central Enrichment Server",
    description=(
        "Receives STINGAR honeypot events and new IP addresses from remote clients, "
        "runs enrichment/scoring/classification, and returns Elasticsearch-ready documents."
    ),
    version="1.1.0",
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


@app.get("/health")
def health():
    cache = get_cache_backend()
    return {
        "status": "ok",
        "service": "central-enrichment-server",
        "cache": cache.stats(),
    }


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


def main():
    import uvicorn

    host = os.getenv("CENTRAL_HOST", "0.0.0.0")
    port = int(os.getenv("CENTRAL_PORT", "8080"))
    uvicorn.run("central.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
