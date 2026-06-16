"""Local webhook listener for STINGAR honeypot nodes."""

from __future__ import annotations

import os
from typing import Any, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request

from stingar.client import StingarEnrichmentClient
from threat_intel.webhook_events import extract_events

load_dotenv()

app = FastAPI(
    title="STINGAR Webhook Listener",
    description=(
        "Receives honeypot events on the STINGAR server and forwards them to the "
        "central enrichment server with local seen-IP deduplication."
    ),
    version="1.0.0",
)

_client: Optional[StingarEnrichmentClient] = None


def get_client() -> StingarEnrichmentClient:
    global _client
    if _client is None:
        central_url = os.getenv("CENTRAL_ENRICHMENT_URL", "http://127.0.0.1:8080")
        client_id = os.getenv("STINGAR_CLIENT_ID", "example-stingar-01")
        sensor_id = os.getenv("STINGAR_SENSOR_ID")
        _client = StingarEnrichmentClient(
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
    return {
        "status": "ok",
        "service": "stingar-webhook-listener",
        "client_id": client.client_id,
        "central_url": client.central_url,
        "seen_ip_count": len(client.seen_store.list_seen_ips()),
    }


@app.post("/webhook/stingar", dependencies=[Depends(require_webhook_secret)])
async def receive_stingar_webhook(request: Request):
    """
    Local STINGAR webhook receiver.

    Point Cowrie/STINGAR HTTP output here. This listener normalizes the payload,
    tracks seen IPs locally, and forwards the batch to central enrichment.
    """
    payload: dict[str, Any] = await request.json()
    client = get_client()
    events = extract_events(payload, default_sensor_id=client.sensor_id)

    if not events:
        raise HTTPException(status_code=400, detail="No events found in webhook payload.")

    try:
        result = client.process_events(events)
    except Exception as error:
        raise HTTPException(status_code=502, detail=f"Central enrichment failed: {error}") from error

    return {
        "status": "accepted",
        "received_events": len(events),
        "local_stats": result.get("local_stats"),
        "enrichment_stats": result.get("enrichment_stats"),
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
