"""Redis-backed primary store for scanner CSV inventory and feed snapshots."""

from __future__ import annotations

import csv
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from threat_intel.scanners import (
    CLASSIFIABLE_CONFIDENCE,
    CLIENT_SCANNERS_DIR,
    DEFAULT_SCANNER_INVENTORY_PATH,
    INVENTORY_COLUMNS,
    SCANNER_FEED_SNAPSHOT_DIR,
    inventory_to_scanner_entries,
    load_scanner_inventory,
)

DEFAULT_REDIS_URL = "redis://127.0.0.1:6379/0"
DEFAULT_PREFIX = "scanner"
DEFAULT_CLIENT_ID = "scanner-lite"


def _vendor_slug(vendor: str) -> str:
    slug = vendor.lower().strip().replace(" ", "-")
    slug = re.sub(r"[^a-z0-9\-]+", "", slug)
    return slug or "unknown"


def scanner_inventory_backend() -> str:
    explicit = os.getenv("SCANNER_INVENTORY_BACKEND", "").strip().lower()
    if explicit in {"redis", "file"}:
        return explicit
    if os.getenv("REDIS_URL") or os.getenv("SCANNER_INVENTORY_BACKEND", "").lower() == "redis":
        return "redis"
    return "file"


class ScannerRedisStore:
    def __init__(
        self,
        redis_url: Optional[str] = None,
        key_prefix: Optional[str] = None,
    ):
        self.redis_url = redis_url or os.getenv("REDIS_URL", DEFAULT_REDIS_URL)
        self.key_prefix = key_prefix or os.getenv("SCANNER_REDIS_PREFIX", DEFAULT_PREFIX)
        self._redis = None

    def _client(self):
        if self._redis is not None:
            return self._redis
        try:
            import redis
        except ImportError as exc:
            raise RuntimeError(
                "Redis scanner inventory requires the redis package. Install with: pip install redis"
            ) from exc
        self._redis = redis.from_url(self.redis_url, decode_responses=True)
        return self._redis

    def _key(self, suffix: str) -> str:
        return f"{self.key_prefix}:{suffix}"

    def ping(self) -> bool:
        try:
            return bool(self._client().ping())
        except Exception:
            return False

    def is_populated(self) -> bool:
        try:
            return bool(self._client().exists(self._key("inventory:meta")))
        except Exception:
            return False

    def load_meta(self) -> dict[str, Any]:
        raw = self._client().get(self._key("inventory:meta"))
        if not raw:
            return {}
        return json.loads(raw)

    def load_csv_rows(self) -> list[dict]:
        raw = self._client().get(self._key("inventory:csv"))
        if not raw:
            return []
        return json.loads(raw)

    def load_feed_snapshot(self, vendor: str) -> dict[str, Any]:
        raw = self._client().get(self._key(f"inventory:feed:{_vendor_slug(vendor)}"))
        if not raw:
            return {}
        return json.loads(raw)

    def load_all_feed_snapshots(self) -> list[dict[str, Any]]:
        pattern = self._key("inventory:feed:*")
        client = self._client()
        snapshots: list[dict[str, Any]] = []
        for key in client.scan_iter(match=pattern, count=200):
            raw = client.get(key)
            if raw:
                snapshots.append(json.loads(raw))
        return sorted(snapshots, key=lambda item: item.get("vendor", ""))

    def feed_snapshots_to_rows(self, snapshots: Optional[list[dict[str, Any]]] = None) -> list[dict]:
        rows: list[dict] = []
        for payload in snapshots or self.load_all_feed_snapshots():
            vendor = payload.get("vendor", "")
            if not vendor:
                continue
            for cidr in payload.get("cidrs", []):
                rows.append(
                    {
                        "vendor": vendor,
                        "scanner_type": payload.get("scanner_type", "internet_scanning"),
                        "cidr": cidr,
                        "source_url": payload.get("source_url", ""),
                        "last_verified": payload.get("last_verified", ""),
                        "confidence": payload.get("confidence", "medium"),
                    }
                )
        return rows

    def load_compiled_registry(self, client_id: str = DEFAULT_CLIENT_ID) -> list[dict]:
        raw = self._client().get(self._key(f"registry:{client_id}"))
        if not raw:
            return []
        return json.loads(raw)

    def publish_inventory(
        self,
        csv_rows: list[dict],
        feed_snapshots: list[dict[str, Any]],
        compiled_by_client: Optional[dict[str, list[dict]]] = None,
        *,
        es_sync_index: str = "",
        es_doc_count: int = 0,
    ) -> dict[str, Any]:
        client = self._client()
        previous_meta = self.load_meta() if self.is_populated() else {}
        version = int(previous_meta.get("version", 0)) + 1
        refreshed_at = datetime.now(timezone.utc).isoformat()
        feed_vendors = sorted({snap.get("vendor", "") for snap in feed_snapshots if snap.get("vendor")})

        meta = {
            "version": version,
            "refreshed_at": refreshed_at,
            "csv_row_count": len(csv_rows),
            "feed_vendors": feed_vendors,
            "feed_snapshot_count": len(feed_snapshots),
            "es_sync_index": es_sync_index,
            "es_doc_count": es_doc_count,
        }

        pipe = client.pipeline()
        pipe.set(self._key("inventory:meta"), json.dumps(meta))
        pipe.set(self._key("inventory:csv"), json.dumps(csv_rows))

        existing_feed_keys = set(client.scan_iter(match=self._key("inventory:feed:*"), count=200))
        next_feed_keys = set()
        for snapshot in feed_snapshots:
            vendor = snapshot.get("vendor", "")
            if not vendor:
                continue
            feed_key = self._key(f"inventory:feed:{_vendor_slug(vendor)}")
            next_feed_keys.add(feed_key)
            payload = dict(snapshot)
            payload.setdefault("refreshed_at", refreshed_at)
            pipe.set(feed_key, json.dumps(payload))

        for stale_key in existing_feed_keys - next_feed_keys:
            pipe.delete(stale_key)

        compiled = compiled_by_client or {}
        if DEFAULT_CLIENT_ID not in compiled:
            feed_rows = self.feed_snapshots_to_rows(feed_snapshots)
            compiled[DEFAULT_CLIENT_ID] = inventory_to_scanner_entries(csv_rows, feed_rows)

        for cid, entries in compiled.items():
            pipe.set(self._key(f"registry:{cid}"), json.dumps(entries))

        pipe.execute()
        return meta

    def publish_from_files(
        self,
        inventory_path: Path = DEFAULT_SCANNER_INVENTORY_PATH,
        feed_dir: Path = SCANNER_FEED_SNAPSHOT_DIR,
        client_ids: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        csv_rows = load_scanner_inventory(inventory_path)
        feed_snapshots: list[dict[str, Any]] = []
        if feed_dir.exists():
            for snapshot_path in sorted(feed_dir.glob("*.json")):
                payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
                if payload.get("vendor"):
                    feed_snapshots.append(payload)

        feed_rows = []
        for payload in feed_snapshots:
            for cidr in payload.get("cidrs", []):
                feed_rows.append(
                    {
                        "vendor": payload["vendor"],
                        "scanner_type": payload.get("scanner_type", "internet_scanning"),
                        "cidr": cidr,
                        "source_url": payload.get("source_url", ""),
                        "last_verified": payload.get("last_verified", ""),
                        "confidence": payload.get("confidence", "medium"),
                    }
                )

        compiled: dict[str, list[dict]] = {}
        default_entries = inventory_to_scanner_entries(csv_rows, feed_rows)
        for client_id in client_ids or [DEFAULT_CLIENT_ID]:
            client_scanners = []
            client_path = CLIENT_SCANNERS_DIR / f"{client_id}_scanners.json"
            if client_path.exists():
                client_payload = json.loads(client_path.read_text(encoding="utf-8"))
                client_scanners = client_payload.get("scanners", [])
            merged = {entry["id"]: entry for entry in default_entries}
            for entry in client_scanners:
                merged[entry["id"]] = entry
            compiled[client_id] = list(merged.values())

        return self.publish_inventory(csv_rows, feed_snapshots, compiled)

    def export_to_files(
        self,
        inventory_path: Path = DEFAULT_SCANNER_INVENTORY_PATH,
        feed_dir: Path = SCANNER_FEED_SNAPSHOT_DIR,
    ) -> dict[str, int]:
        csv_rows = self.load_csv_rows()
        snapshots = self.load_all_feed_snapshots()

        inventory_path.parent.mkdir(parents=True, exist_ok=True)
        with inventory_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(INVENTORY_COLUMNS))
            writer.writeheader()
            for row in csv_rows:
                writer.writerow({column: row.get(column, "") for column in INVENTORY_COLUMNS})

        feed_dir.mkdir(parents=True, exist_ok=True)
        for snapshot in snapshots:
            vendor = snapshot.get("vendor", "")
            if not vendor:
                continue
            path = feed_dir / f"{_vendor_slug(vendor)}.json"
            payload = dict(snapshot)
            payload["cidr_count"] = len(payload.get("cidrs", []))
            path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

        return {"csv_rows": len(csv_rows), "feed_snapshots": len(snapshots)}

    def build_publish_payload(self) -> dict[str, Any]:
        csv_rows = self.load_csv_rows()
        feed_snapshots = self.load_all_feed_snapshots()
        feed_rows = self.feed_snapshots_to_rows(feed_snapshots)
        classifiable_rows = [
            row
            for row in csv_rows + feed_rows
            if row.get("cidr") and row.get("confidence", "").lower() in CLASSIFIABLE_CONFIDENCE
        ]
        return {
            "meta": self.load_meta(),
            "csv_rows": csv_rows,
            "feed_snapshots": feed_snapshots,
            "classifiable_rows": classifiable_rows,
        }

    def update_es_sync(self, es_sync_index: str, es_doc_count: int) -> dict[str, Any]:
        meta = self.load_meta()
        if not meta:
            return {}
        meta["es_sync_index"] = es_sync_index
        meta["es_doc_count"] = es_doc_count
        self._client().set(self._key("inventory:meta"), json.dumps(meta))
        return meta

    def stats(self) -> dict[str, Any]:
        meta = self.load_meta()
        feed_snapshots = self.load_all_feed_snapshots()
        feed_range_count = sum(len(s.get("cidrs", [])) for s in feed_snapshots)
        return {
            "backend": "redis",
            "redis_url": self.redis_url,
            "key_prefix": self.key_prefix,
            "populated": self.is_populated(),
            "redis_reachable": self.ping(),
            "inventory_version": meta.get("version"),
            "refreshed_at": meta.get("refreshed_at"),
            "csv_row_count": meta.get("csv_row_count", len(self.load_csv_rows())),
            "feed_vendor_count": len(feed_snapshots),
            "feed_range_count": feed_range_count,
            "es_sync_index": meta.get("es_sync_index"),
            "es_doc_count": meta.get("es_doc_count"),
        }


_store_instance: Optional[ScannerRedisStore] = None


def get_scanner_redis_store() -> ScannerRedisStore:
    global _store_instance
    if _store_instance is None:
        _store_instance = ScannerRedisStore()
    return _store_instance


def get_inventory_meta() -> dict[str, Any]:
    if scanner_inventory_backend() != "redis":
        return {}
    store = get_scanner_redis_store()
    if not store.is_populated():
        return {}
    return store.load_meta()


def get_inventory_version() -> Optional[int]:
    meta = get_inventory_meta()
    version = meta.get("version")
    return int(version) if version is not None else None
