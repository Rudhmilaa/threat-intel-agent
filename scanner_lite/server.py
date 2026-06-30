"""FastAPI server for scanner enrichment lite."""

from __future__ import annotations

import os
from typing import Any, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field

from scanner_lite.enrich import enrich_events, enrich_ip
from scanner_lite.eval.overlap import RANKING_PATH, run_overlap_eval
from scanner_lite.fluentd_normalize import normalize_fluentd_payload
from scanner_lite.stingar_ingest import process_stingar_payload
from scanner_lite.storage.es_store import ScannerLiteStore
from scanner_lite.storage.inventory_es_store import ScannerInventoryEsStore
from threat_intel.scanners import ScannerRegistry, configure_scanners, get_active_registry
from threat_intel.scanner_redis_store import get_scanner_redis_store, scanner_inventory_backend

load_dotenv()

app = FastAPI(title="Scanner Enrichment Lite", version="0.1.0")


class EnrichIpRequest(BaseModel):
    ip_address: str
    client_id: str = "scanner-lite"


class EnrichEventsRequest(BaseModel):
    client_id: str = "scanner-lite"
    events: list[dict] = Field(default_factory=list)


def _store() -> ScannerLiteStore:
    return ScannerLiteStore()


class WebhookAuthConfig:
    def __init__(self) -> None:
        self.webhook_secret = os.getenv("STINGAR_WEBHOOK_SECRET")

    def verify(self, request: Request) -> None:
        if not self.webhook_secret:
            return
        provided = request.headers.get("X-Webhook-Secret")
        if provided != self.webhook_secret:
            raise HTTPException(status_code=401, detail="Invalid webhook secret.")


auth_config = WebhookAuthConfig()


def require_webhook_secret(request: Request) -> None:
    auth_config.verify(request)


def _scanner_lite_client_id() -> str:
    return os.getenv("STINGAR_CLIENT_ID", "scanner-lite")


def _scanner_lite_sensor_id() -> Optional[str]:
    return os.getenv("STINGAR_SENSOR_ID")


@app.on_event("startup")
def startup() -> None:
    store = _store()
    if store.ping():
        store.ensure_templates()

    client_id = _scanner_lite_client_id()
    if scanner_inventory_backend() == "redis":
        redis_store = get_scanner_redis_store()
        if not redis_store.is_populated():
            redis_store.publish_from_files()
        configure_scanners(ScannerRegistry.from_redis(client_id))
    else:
        configure_scanners(ScannerRegistry.for_client(client_id))


@app.get("/health")
def health() -> dict[str, Any]:
    store = _store()
    payload: dict[str, Any] = {
        "status": "ok",
        "service": "scanner-enrichment-lite",
        "storage": "elasticsearch",
        **store.stats(),
    }
    if scanner_inventory_backend() == "redis":
        redis_store = get_scanner_redis_store()
        scanner_stats = redis_store.stats()
        payload["scanner_cache"] = scanner_stats
        payload["scanner_inventory_backend"] = "redis"
        if not scanner_stats.get("populated"):
            payload["status"] = "degraded"
            payload["scanner_cache_warning"] = (
                "Redis scanner inventory is empty; run scripts/seed-scanner-redis.py"
            )
        try:
            payload["scanner_inventory_es"] = ScannerInventoryEsStore().stats()
        except Exception as error:
            payload["scanner_inventory_es"] = {"error": str(error)}
    else:
        payload["scanner_inventory_backend"] = "file"
    return payload


@app.get("/scanner-lite/inventory/meta")
def inventory_meta() -> dict[str, Any]:
    """Redis inventory meta plus Elasticsearch sync stats for audit/demo."""
    if scanner_inventory_backend() != "redis":
        raise HTTPException(status_code=404, detail="Scanner inventory backend is not Redis.")
    redis_store = get_scanner_redis_store()
    if not redis_store.is_populated():
        raise HTTPException(status_code=503, detail="Scanner Redis inventory is not populated.")
    meta = redis_store.load_meta()
    es_stats = ScannerInventoryEsStore().stats()
    return {
        "meta": meta,
        "redis": redis_store.stats(),
        "elasticsearch": es_stats,
        "registry_range_count": len(get_active_registry().scanner_table()),
    }


@app.post("/scanner-lite/enrich/ip")
def enrich_single_ip(request: EnrichIpRequest) -> dict:
    try:
        return enrich_ip(request.ip_address, client_id=request.client_id, store=_store())
    except Exception as error:
        raise HTTPException(status_code=502, detail=str(error)) from error


@app.post("/scanner-lite/enrich/events")
def enrich_batch(request: EnrichEventsRequest) -> dict:
    if not request.events:
        raise HTTPException(status_code=400, detail="events list is required")
    try:
        return enrich_events(request.events, client_id=request.client_id, store=_store())
    except Exception as error:
        raise HTTPException(status_code=502, detail=str(error)) from error


@app.get("/scanner-lite/batches/asn")
def get_asn_batches(date: Optional[str] = Query(default=None)) -> dict:
    from datetime import datetime, timezone

    batch_date = date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    batches = _store().search_asn_batches(batch_date)
    return {"batch_date": batch_date, "count": len(batches), "batches": batches}


@app.get("/scanner-lite/sessions")
def search_sessions(
    q: str = Query(default=""),
    hours: int = Query(default=24, ge=1, le=168),
    size: int = Query(default=50, ge=1, le=200),
    client_id: Optional[str] = Query(default=None),
) -> dict:
    """Search stingar-enriched session records written by scanner-lite enrichment."""
    from threat_intel.elasticsearch.document_store import ElasticsearchDocumentStore

    cid = client_id or _scanner_lite_client_id()
    try:
        return ElasticsearchDocumentStore().search_sessions(
            q,
            client_id=cid,
            hours=hours,
            size=size,
        )
    except Exception as error:
        raise HTTPException(status_code=502, detail=str(error)) from error


@app.get("/scanner-lite/eval/ranking")
def get_eval_ranking() -> dict:
    if RANKING_PATH.exists():
        import json

        return json.loads(RANKING_PATH.read_text(encoding="utf-8"))
    return {"cascade_order": [], "ranking": [], "notes": "Run eval/overlap.py first"}


@app.post("/scanner-lite/eval/run")
def run_eval() -> dict:
    try:
        return run_overlap_eval(write_ranking=True)
    except Exception as error:
        raise HTTPException(status_code=502, detail=str(error)) from error


def _stingar_ingest_response(result: dict) -> dict:
    return {
        "status": result["status"],
        "service": result["service"],
        "received_events": result["received_events"],
        "enriched_count": result["enriched_count"],
        "category_counts": result["category_counts"],
        "total_api_calls": result["total_api_calls"],
        "es_stats": result["es_stats"],
        "session_es_stats": result.get("session_es_stats"),
    }


@app.post("/webhook/stingar", dependencies=[Depends(require_webhook_secret)])
async def receive_stingar_webhook(request: Request) -> dict:
    payload = await request.json()
    try:
        result = process_stingar_payload(
            payload,
            client_id=_scanner_lite_client_id(),
            sensor_id=_scanner_lite_sensor_id(),
            store=_store(),
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=502, detail=f"Enrichment failed: {error}") from error

    return _stingar_ingest_response(result)


@app.post("/webhook/stingar/batch", dependencies=[Depends(require_webhook_secret)])
async def receive_stingar_batch(request: Request) -> dict:
    return await receive_stingar_webhook(request)


@app.post("/ingest/fluentd")
async def receive_fluentd_ingest(request: Request) -> dict:
    """Accept Fluentd out_http JSON records and enrich into stingar-* session indices."""
    payload = await request.json()
    normalized = normalize_fluentd_payload(payload)
    try:
        result = process_stingar_payload(
            normalized,
            client_id=_scanner_lite_client_id(),
            sensor_id=_scanner_lite_sensor_id(),
            store=_store(),
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    except Exception as error:
        raise HTTPException(status_code=502, detail=f"Enrichment failed: {error}") from error
    return _stingar_ingest_response(result)


def main() -> None:
    import uvicorn

    host = os.getenv("SCANNER_LITE_HOST", "127.0.0.1")
    port = int(os.getenv("SCANNER_LITE_PORT", "8091"))
    uvicorn.run("scanner_lite.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
