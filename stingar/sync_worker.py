"""Drain the offline sync queue when central is reachable."""

from __future__ import annotations

import os

import requests
from dotenv import load_dotenv

from stingar.sync_queue import SyncQueue

load_dotenv()


def drain_sync_queue(
    central_url: str | None = None,
    api_key: str | None = None,
    queue: SyncQueue | None = None,
    limit: int = 50,
) -> dict:
    central_url = (central_url or os.getenv("CENTRAL_ENRICHMENT_URL", "http://127.0.0.1:8080")).rstrip("/")
    api_key = api_key or os.getenv("CENTRAL_API_KEY")
    queue = queue or SyncQueue()

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    sent = 0
    failed = 0
    results = []

    for item in queue.list_pending(limit=limit):
        try:
            response = requests.post(
                f"{central_url}/api/v1/sync/events",
                json=item["payload"],
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            queue.mark_sent(item["id"])
            sent += 1
            results.append({"id": item["id"], "status": "sent"})
        except Exception as error:
            queue.mark_failed(item["id"], str(error))
            failed += 1
            results.append({"id": item["id"], "status": "failed", "error": str(error)})

    return {
        "sent": sent,
        "failed": failed,
        "queue_stats": queue.stats(),
        "results": results,
    }


def main():
    summary = drain_sync_queue()
    print(summary)


if __name__ == "__main__":
    main()
