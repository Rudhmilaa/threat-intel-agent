"""Known scanner registry with global defaults and per-client CIDR tables."""

from __future__ import annotations

import ipaddress
import json
from copy import deepcopy
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCANNERS_PATH = PROJECT_ROOT / "config" / "scanners" / "default_scanners.json"
CLIENT_SCANNERS_DIR = PROJECT_ROOT / "config" / "clients"


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
    }


class ScannerRegistry:
    """
    Loads global scanner CIDR tables and merges client-specific tables.

    Client scanners with the same `id` override the default entry.
    """

    def __init__(
        self,
        default_scanners: list[dict],
        client_scanners: Optional[list[dict]] = None,
        client_id: Optional[str] = None,
    ):
        self.client_id = client_id
        self._scanners = self._merge_tables(default_scanners, client_scanners or [])

    @classmethod
    def from_files(
        cls,
        client_id: Optional[str] = None,
        default_path: Path = DEFAULT_SCANNERS_PATH,
        client_dir: Path = CLIENT_SCANNERS_DIR,
    ) -> "ScannerRegistry":
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

    def scanner_table(self) -> list[dict]:
        """Flatten scanners into one row per CIDR range for analyst review."""
        rows = []
        for scanner in self.list_scanners():
            for cidr in scanner["ranges"]:
                rows.append(
                    {
                        "scanner_id": scanner["id"],
                        "company": scanner["company"],
                        "category": scanner["category"],
                        "classification": scanner["classification"],
                        "default_severity": scanner["default_severity"],
                        "source": scanner["source"],
                        "cidr": cidr,
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
