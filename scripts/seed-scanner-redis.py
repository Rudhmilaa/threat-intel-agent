#!/usr/bin/env python3
"""Bootstrap scanner inventory from on-disk CSV/feeds into Redis and Elasticsearch."""

from __future__ import annotations

import argparse
import json
import sys

from scanner_lite.storage.inventory_es_store import ScannerInventoryEsStore
from threat_intel.scanner_redis_store import get_scanner_redis_store


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed scanner inventory from files into Redis.")
    parser.add_argument(
        "--skip-es",
        action="store_true",
        help="Publish to Redis only; skip Elasticsearch scanner-inventory sync.",
    )
    args = parser.parse_args()

    store = get_scanner_redis_store()
    if not store.ping():
        print("Redis is not reachable. Set REDIS_URL and start Redis first.", file=sys.stderr)
        return 1

    meta = store.publish_from_files()
    payload = store.build_publish_payload()
    es_result: dict = {"skipped": True}
    if not args.skip_es:
        es_result = ScannerInventoryEsStore().sync_from_publish(payload)
        store.update_es_sync(es_result.get("index", ""), es_result.get("indexed", 0))

    print(
        json.dumps(
            {
                "status": "ok",
                "inventory_version": meta.get("version"),
                "refreshed_at": meta.get("refreshed_at"),
                "csv_row_count": meta.get("csv_row_count"),
                "feed_snapshot_count": meta.get("feed_snapshot_count"),
                "es_sync": es_result,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
