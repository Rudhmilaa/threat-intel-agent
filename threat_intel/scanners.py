"""Known scanner registry with CSV inventory and per-client CIDR overrides."""

from __future__ import annotations

import csv
import ipaddress
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCANNERS_PATH = PROJECT_ROOT / "config" / "scanners" / "default_scanners.json"
DEFAULT_SCANNER_INVENTORY_PATH = PROJECT_ROOT / "config" / "scanners" / "known_scanner_inventory.csv"
SCANNER_FEED_SNAPSHOT_DIR = PROJECT_ROOT / "config" / "scanners" / "feeds"
CLIENT_SCANNERS_DIR = PROJECT_ROOT / "config" / "clients"

INVENTORY_COLUMNS = (
    "vendor",
    "scanner_type",
    "cidr",
    "source_url",
    "last_verified",
    "confidence",
)

CLASSIFIABLE_CONFIDENCE = {"high", "medium"}


def _vendor_to_scanner_id(vendor: str) -> str:
    slug = vendor.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")


def _validate_scanner_entry(entry: dict) -> dict:
    required = {"id", "company", "ranges"}
    missing = required - set(entry.keys())
    if missing:
        raise ValueError(f"Scanner entry missing fields: {sorted(missing)}")

    validated_ranges = []
    for cidr in entry["ranges"]:
        ipaddress.ip_network(cidr, strict=False)
        validated_ranges.append(str(cidr))

    return {
        "id": entry["id"],
        "company": entry["company"],
        "category": entry.get("category", "unknown_scanner"),
        "classification": entry.get("classification", "known_scanner"),
        "default_severity": entry.get("default_severity", "LOW"),
        "source": entry.get("source", "client"),
        "ranges": validated_ranges,
        "notes": entry.get("notes", ""),
        "range_metadata": entry.get("range_metadata", {}),
    }


def load_scanner_inventory(
    inventory_path: Path = DEFAULT_SCANNER_INVENTORY_PATH,
) -> list[dict]:
    """Load the full scanner inventory spreadsheet, including rows without CIDRs."""
    if not inventory_path.exists():
        return []

    rows: list[dict] = []
    with inventory_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            normalized = {column: (row.get(column) or "").strip() for column in INVENTORY_COLUMNS}
            if not normalized["vendor"]:
                continue
            rows.append(normalized)
    return rows


def load_scanner_feed_snapshots(
    feed_dir: Path = SCANNER_FEED_SNAPSHOT_DIR,
) -> list[dict]:
    """Load auto-maintained dynamic vendor feed snapshots written by maintenance."""
    if not feed_dir.exists():
        return []

    rows: list[dict] = []
    for snapshot_path in sorted(feed_dir.glob("*.json")):
        payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
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


def inventory_to_scanner_entries(
    inventory_rows: list[dict],
    feed_snapshot_rows: Optional[list[dict]] = None,
) -> list[dict]:
    """
    Group inventory rows into scanner registry entries.

    Only high/medium-confidence rows with valid CIDRs are used for IP matching.
    """
    grouped: dict[str, dict] = {}

    for row in inventory_rows + (feed_snapshot_rows or []):
        scanner_id = _vendor_to_scanner_id(row["vendor"])
        confidence = row["confidence"].lower()
        cidr = row["cidr"]

        if scanner_id not in grouped:
            grouped[scanner_id] = {
                "id": scanner_id,
                "company": row["vendor"],
                "category": row["scanner_type"],
                "classification": "known_scanner",
                "default_severity": "LOW",
                "source": "inventory",
                "ranges": [],
                "notes": (
                    f"Maintained in known_scanner_inventory.csv. "
                    f"Primary source: {row['source_url'] or 'not documented'}."
                ),
                "range_metadata": {},
            }

        if not cidr:
            continue

        if confidence not in CLASSIFIABLE_CONFIDENCE:
            continue

        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue

        scanner = grouped[scanner_id]
        if cidr not in scanner["ranges"]:
            scanner["ranges"].append(cidr)
        scanner["range_metadata"][cidr] = {
            "source_url": row["source_url"],
            "last_verified": row["last_verified"],
            "confidence": confidence,
            "scanner_type": row["scanner_type"],
        }

    return [entry for entry in grouped.values() if entry["ranges"]]


class ScannerRegistry:
    """
    Loads scanner inventory CSV and merges client-specific JSON overrides.

    Client scanners with the same `id` override the default entry.
    """

    def __init__(
        self,
        default_scanners: list[dict],
        client_scanners: Optional[list[dict]] = None,
        client_id: Optional[str] = None,
        inventory_rows: Optional[list[dict]] = None,
    ):
        self.client_id = client_id
        self._inventory_rows = inventory_rows or []
        self._scanners = self._merge_tables(default_scanners, client_scanners or [])

    @classmethod
    def from_inventory(
        cls,
        client_id: Optional[str] = None,
        inventory_path: Path = DEFAULT_SCANNER_INVENTORY_PATH,
        client_dir: Path = CLIENT_SCANNERS_DIR,
    ) -> "ScannerRegistry":
        inventory_rows = load_scanner_inventory(inventory_path)
        feed_snapshot_rows = load_scanner_feed_snapshots()
        default_scanners = inventory_to_scanner_entries(inventory_rows, feed_snapshot_rows)

        client_scanners = []
        if client_id:
            client_path = client_dir / f"{client_id}_scanners.json"
            if client_path.exists():
                client_payload = json.loads(client_path.read_text(encoding="utf-8"))
                client_scanners = client_payload.get("scanners", [])

        return cls(default_scanners, client_scanners, client_id, inventory_rows)

    @classmethod
    def from_redis(
        cls,
        client_id: Optional[str] = None,
        client_dir: Path = CLIENT_SCANNERS_DIR,
    ) -> "ScannerRegistry":
        from threat_intel.scanner_redis_store import get_scanner_redis_store

        store = get_scanner_redis_store()
        if not store.is_populated():
            raise RuntimeError(
                "Scanner Redis inventory is empty. Run scripts/seed-scanner-redis.py or "
                "python -m threat_intel.scanner_inventory_maintenance first."
            )

        inventory_rows = store.load_csv_rows()
        resolved_client = client_id or "scanner-lite"
        default_scanners = store.load_compiled_registry(resolved_client)
        if not default_scanners:
            feed_rows = store.feed_snapshots_to_rows()
            default_scanners = inventory_to_scanner_entries(inventory_rows, feed_rows)

        client_scanners = []
        if client_id:
            client_path = client_dir / f"{client_id}_scanners.json"
            if client_path.exists():
                client_payload = json.loads(client_path.read_text(encoding="utf-8"))
                client_scanners = client_payload.get("scanners", [])

        return cls(default_scanners, client_scanners, client_id, inventory_rows)

    @classmethod
    def from_files(
        cls,
        client_id: Optional[str] = None,
        default_path: Path = DEFAULT_SCANNERS_PATH,
        inventory_path: Path = DEFAULT_SCANNER_INVENTORY_PATH,
        client_dir: Path = CLIENT_SCANNERS_DIR,
    ) -> "ScannerRegistry":
        if inventory_path.exists():
            return cls.from_inventory(client_id=client_id, inventory_path=inventory_path, client_dir=client_dir)

        default_payload = json.loads(default_path.read_text(encoding="utf-8"))
        default_scanners = default_payload.get("scanners", [])

        client_scanners = []
        if client_id:
            client_path = client_dir / f"{client_id}_scanners.json"
            if client_path.exists():
                client_payload = json.loads(client_path.read_text(encoding="utf-8"))
                client_scanners = client_payload.get("scanners", [])

        return cls(default_scanners, client_scanners, client_id)

    @classmethod
    def for_client(cls, client_id: Optional[str] = None) -> "ScannerRegistry":
        from threat_intel.scanner_redis_store import scanner_inventory_backend

        if scanner_inventory_backend() == "redis":
            try:
                return cls.from_redis(client_id=client_id)
            except RuntimeError:
                pass
        return cls.from_files(client_id=client_id)

    @staticmethod
    def _merge_tables(default_scanners: list[dict], client_scanners: list[dict]) -> dict[str, dict]:
        merged: dict[str, dict] = {}

        for entry in default_scanners:
            validated = _validate_scanner_entry({**entry, "source": entry.get("source", "default")})
            merged[validated["id"]] = validated

        for entry in client_scanners:
            validated = _validate_scanner_entry({**entry, "source": entry.get("source", "client")})
            merged[validated["id"]] = validated

        return merged

    def list_scanners(self) -> list[dict]:
        return sorted(self._scanners.values(), key=lambda item: item["company"].lower())

    def inventory_table(self) -> list[dict]:
        """Return the full scanner inventory spreadsheet for analyst review."""
        if self._inventory_rows:
            return deepcopy(self._inventory_rows)

        rows = []
        for scanner in self.list_scanners():
            for cidr in scanner["ranges"]:
                metadata = scanner.get("range_metadata", {}).get(cidr, {})
                rows.append(
                    {
                        "vendor": scanner["company"],
                        "scanner_type": metadata.get("scanner_type", scanner["category"]),
                        "cidr": cidr,
                        "source_url": metadata.get("source_url", ""),
                        "last_verified": metadata.get("last_verified", ""),
                        "confidence": metadata.get("confidence", "medium"),
                    }
                )
        return rows

    def scanner_table(self) -> list[dict]:
        """Flatten scanners into one row per CIDR range for analyst review."""
        rows = []
        for scanner in self.list_scanners():
            for cidr in scanner["ranges"]:
                metadata = scanner.get("range_metadata", {}).get(cidr, {})
                rows.append(
                    {
                        "scanner_id": scanner["id"],
                        "company": scanner["company"],
                        "category": scanner["category"],
                        "classification": scanner["classification"],
                        "default_severity": scanner["default_severity"],
                        "source": scanner["source"],
                        "cidr": cidr,
                        "source_url": metadata.get("source_url", ""),
                        "last_verified": metadata.get("last_verified", ""),
                        "confidence": metadata.get("confidence", ""),
                        "notes": scanner["notes"],
                    }
                )
        return rows

    def get_scanner(self, scanner_id: str) -> Optional[dict]:
        return self._scanners.get(scanner_id)

    def add_client_scanner(self, scanner_entry: dict, persist: bool = True) -> dict:
        if not self.client_id:
            raise ValueError("client_id is required to add client scanners")

        validated = _validate_scanner_entry({**scanner_entry, "source": "client"})
        self._scanners[validated["id"]] = validated

        if persist:
            self._persist_client_table()

        return validated

    def remove_client_scanner(self, scanner_id: str, persist: bool = True) -> bool:
        if not self.client_id:
            raise ValueError("client_id is required to remove client scanners")

        scanner = self._scanners.get(scanner_id)
        if not scanner or scanner.get("source") != "client":
            return False

        del self._scanners[scanner_id]

        if persist:
            self._persist_client_table()

        return True

    def _persist_client_table(self) -> None:
        CLIENT_SCANNERS_DIR.mkdir(parents=True, exist_ok=True)
        client_path = CLIENT_SCANNERS_DIR / f"{self.client_id}_scanners.json"

        client_scanners = [
            scanner
            for scanner in self._scanners.values()
            if scanner.get("source") == "client"
        ]

        payload = {
            "client_id": self.client_id,
            "description": "Client-specific scanner table merged on top of defaults.",
            "scanners": client_scanners,
        }

        client_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def classify_ip(self, ip_address: str) -> dict:
        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError:
            return {
                "ip": ip_address,
                "is_known_scanner": False,
                "classification": "invalid_ip",
                "default_severity": "UNKNOWN",
                "notes": "Invalid IP address format.",
            }

        best_match = None
        best_prefix = -1

        for scanner in self._scanners.values():
            for network in scanner["ranges"]:
                network_obj = ipaddress.ip_network(network, strict=False)
                if ip_obj in network_obj and network_obj.prefixlen > best_prefix:
                    metadata = scanner.get("range_metadata", {}).get(network, {})
                    best_prefix = network_obj.prefixlen
                    best_match = {
                        "ip": ip_address,
                        "is_known_scanner": True,
                        "scanner_id": scanner["id"],
                        "company": scanner["company"],
                        "category": scanner["category"],
                        "classification": scanner["classification"],
                        "default_severity": scanner["default_severity"],
                        "matched_range": str(network_obj),
                        "source": scanner["source"],
                        "source_url": metadata.get("source_url", ""),
                        "last_verified": metadata.get("last_verified", ""),
                        "confidence": metadata.get("confidence", ""),
                        "notes": scanner["notes"],
                    }

        if best_match:
            return best_match

        return {
            "ip": ip_address,
            "is_known_scanner": False,
            "classification": "not_known_scanner",
            "default_severity": "UNKNOWN",
            "notes": "IP did not match known scanner ranges in the active scanner table.",
        }


_active_registry: Optional[ScannerRegistry] = None


def configure_scanners(registry: ScannerRegistry) -> None:
    global _active_registry
    _active_registry = registry


def get_active_registry() -> ScannerRegistry:
    global _active_registry
    if _active_registry is None:
        _active_registry = ScannerRegistry.for_client()
    return _active_registry


def classify_known_scanner(ip_address: str, registry: Optional[ScannerRegistry] = None) -> dict:
    active = registry or get_active_registry()
    return active.classify_ip(ip_address)


def list_scanner_inventory(registry: Optional[ScannerRegistry] = None) -> dict:
    """Return the scanner inventory spreadsheet plus classification coverage stats."""
    active = registry or get_active_registry()
    inventory = active.inventory_table()
    feed_snapshot_rows = load_scanner_feed_snapshots()
    classifiable_ranges = sum(
        1
        for row in inventory + feed_snapshot_rows
        if row.get("cidr") and row.get("confidence", "").lower() in CLASSIFIABLE_CONFIDENCE
    )
    vendors = sorted({row["vendor"] for row in inventory + feed_snapshot_rows})
    pending_vendors = sorted(
        {
            row["vendor"]
            for row in inventory
            if not row.get("cidr") or row.get("confidence", "").lower() not in CLASSIFIABLE_CONFIDENCE
        }
    )

    return {
        "inventory_path": str(DEFAULT_SCANNER_INVENTORY_PATH),
        "feed_snapshot_dir": str(SCANNER_FEED_SNAPSHOT_DIR),
        "vendor_count": len(vendors),
        "inventory_row_count": len(inventory),
        "feed_snapshot_range_count": len(feed_snapshot_rows),
        "classifiable_range_count": classifiable_ranges,
        "vendors": vendors,
        "pending_or_dynamic_vendors": pending_vendors,
        "maintenance_notes": (
            "Only high/medium-confidence CIDRs with a documented source_url are used for "
            "automatic classification. Run refresh_scanner_inventory (agent tool, API, or "
            "python -m threat_intel.scanner_inventory_maintenance) to sync official feeds."
        ),
        "inventory": inventory,
        "feed_snapshots_preview": feed_snapshot_rows[:25],
    }
