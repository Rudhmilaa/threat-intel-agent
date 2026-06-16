"""Central threat intelligence enrichment server."""

from __future__ import annotations

import os
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from threat_intel.pipeline import enrich_events_for_client, enrich_ip_for_client, enrich_ips_for_client
from threat_intel.protocols import (
    build_enrich_ip_response,
    build_scanner_table_response,
    validate_honeypot_event,
)
from threat_intel.scanners import ScannerRegistry

load_dotenv()

app = FastAPI(
    title="Threat Intelligence Central Enrichment Server",
    description=(
        "Receives STINGAR honeypot events and new IP addresses from remote clients, "
        "runs enrichment/scoring/classification, and returns Elasticsearch-ready documents."
    ),
    version="1.0.0",
)

_central_intelligence_cache: dict[str, dict] = {}


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


class RemoveScannerRequest(BaseModel):
    client_id: str


@app.get("/health")
def health():
    return {"status": "ok", "service": "central-enrichment-server"}


@app.post("/api/v1/enrich/events")
def enrich_events(request: EnrichEventsRequest):
    validation_errors = []
    for index, event in enumerate(request.events):
        errors = validate_honeypot_event(event)
        for error in errors:
            validation_errors.append(f"events[{index}]: {error}")

    if validation_errors:
        raise HTTPException(status_code=400, detail=validation_errors)

    client_cache = _central_intelligence_cache.setdefault(request.client_id, {})
    result = enrich_events_for_client(
        events=request.events,
        client_id=request.client_id,
        new_ips=request.new_ips,
        intelligence_cache=client_cache,
    )
    _central_intelligence_cache[request.client_id] = result.pop("intelligence_cache")
    return result


@app.post("/api/v1/enrich/ip")
def enrich_ip(request: EnrichIpRequest):
    summary = enrich_ip_for_client(request.ip_address, request.client_id)
    return build_enrich_ip_response(request.client_id, request.ip_address, summary)


@app.post("/api/v1/enrich/ips")
def enrich_ips(request: EnrichIpsRequest):
    return enrich_ips_for_client(request.ip_addresses, request.client_id)


@app.get("/api/v1/scanners")
def list_scanners(client_id: Optional[str] = None):
    registry = ScannerRegistry.for_client(client_id)
    return {
        "client_id": client_id,
        "scanners": registry.list_scanners(),
    }


@app.get("/api/v1/scanners/table")
def scanner_table(client_id: Optional[str] = None):
    registry = ScannerRegistry.for_client(client_id)
    return build_scanner_table_response(client_id, registry.scanner_table())


@app.post("/api/v1/scanners")
def add_client_scanner(request: ScannerEntryRequest):
    registry = ScannerRegistry.for_client(request.client_id)
    try:
        created = registry.add_client_scanner(request.scanner, persist=True)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    return {"client_id": request.client_id, "scanner": created}


@app.delete("/api/v1/scanners/{scanner_id}")
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
