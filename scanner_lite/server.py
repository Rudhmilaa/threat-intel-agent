"""FastAPI server for scanner enrichment lite."""

from __future__ import annotations

import os
from typing import Any, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, Field

from scanner_lite.enrich import enrich_events, enrich_ip
from scanner_lite.eval.overlap import RANKING_PATH, run_overlap_eval
from scanner_lite.stingar_ingest import process_stingar_payload
from scanner_lite.storage.es_store import ScannerLiteStore

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


@app.get("/health")
def health() -> dict[str, Any]:
    store = _store()
    return {
        "status": "ok",
        "service": "scanner-enrichment-lite",
        "storage": "elasticsearch",
        **store.stats(),
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

    return {
        "status": result["status"],
        "service": result["service"],
        "received_events": result["received_events"],
        "enriched_count": result["enriched_count"],
        "category_counts": result["category_counts"],
        "total_api_calls": result["total_api_calls"],
        "es_stats": result["es_stats"],
    }


@app.post("/webhook/stingar/batch", dependencies=[Depends(require_webhook_secret)])
async def receive_stingar_batch(request: Request) -> dict:
    return await receive_stingar_webhook(request)


def main() -> None:
    import uvicorn

    host = os.getenv("SCANNER_LITE_HOST", "127.0.0.1")
    port = int(os.getenv("SCANNER_LITE_PORT", "8091"))
    uvicorn.run("scanner_lite.server:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
