"""Local webhook listener for STINGAR honeypot nodes."""

from __future__ import annotations

import os
from typing import Any, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request

from stingar.client import HybridEnrichmentClient
from threat_intel.storage import elasticsearch_available, get_intelligence_cache, storage_backend_name
from threat_intel.webhook_events import extract_events

load_dotenv()

app = FastAPI(
    title="STINGAR Webhook Listener",
    description=(
        "Receives honeypot events on the STINGAR server, enriches locally first, "
        "and optionally syncs sanitized payloads to central."
    ),
    version="1.1.0",
)

_client: Optional[HybridEnrichmentClient] = None


def get_client() -> HybridEnrichmentClient:
    global _client
    if _client is None:
        central_url = os.getenv("CENTRAL_ENRICHMENT_URL", "http://127.0.0.1:8080")
        client_id = os.getenv("STINGAR_CLIENT_ID", "example-stingar-01")
        sensor_id = os.getenv("STINGAR_SENSOR_ID")
        _client = HybridEnrichmentClient(
            central_url=central_url,
            client_id=client_id,
            sensor_id=sensor_id,
        )
    return _client


class WebhookAuthConfig:
    def __init__(self):
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


@app.get("/health")
def health():
    client = get_client()
    payload = {
        "status": "ok",
        "service": "stingar-webhook-listener",
        "client_id": client.client_id,
        "deployment_mode": client.deployment_mode,
        "storage_backend": storage_backend_name(),
        "central_url": client.central_url or None,
        "intelligence_cache": get_intelligence_cache().stats(),
        "sync_queue": client.sync_queue.stats(),
    }
    if storage_backend_name() == "elasticsearch":
        payload["elasticsearch_reachable"] = elasticsearch_available()
    return payload


@app.post("/webhook/stingar", dependencies=[Depends(require_webhook_secret)])
async def receive_stingar_webhook(request: Request):
    payload: dict[str, Any] = await request.json()
    client = get_client()
    events = extract_events(payload, default_sensor_id=client.sensor_id)

    if not events:
        raise HTTPException(status_code=400, detail="No events found in webhook payload.")

    try:
        result = client.process_events(events)
    except Exception as error:
        raise HTTPException(status_code=502, detail=f"Local enrichment failed: {error}") from error

    return {
        "status": "accepted",
        "enrichment_source": result.get("enrichment_source", "local"),
        "storage_backend": result.get("storage_backend"),
        "received_events": len(events),
        "local_stats": result.get("local_stats"),
        "enrichment_stats": result.get("enrichment_stats"),
        "es_stats": result.get("es_stats"),
        "storage_warnings": result.get("storage_warnings"),
        "sync": result.get("sync"),
        "prioritized_incidents": len(result.get("prioritized_incidents", [])),
    }


@app.post("/webhook/stingar/batch", dependencies=[Depends(require_webhook_secret)])
async def receive_stingar_batch(request: Request):
    return await receive_stingar_webhook(request)


def main():
    import argparse
    import uvicorn

    parser = argparse.ArgumentParser(description="STINGAR local webhook listener")
    parser.add_argument("--host", default=os.getenv("STINGAR_WEBHOOK_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.getenv("STINGAR_WEBHOOK_PORT", "8090")))
    args = parser.parse_args()

    uvicorn.run("stingar.webhook_listener:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    main()
