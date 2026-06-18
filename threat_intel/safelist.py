"""Safelist registry for CIDR ranges that must never be blocked or escalated."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SAFELIST_PATH = PROJECT_ROOT / "config" / "safelist" / "default_safelist.json"
CLIENT_CONFIG_DIR = PROJECT_ROOT / "config" / "clients"

SEVERITY_RANK = {
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _validate_entry(entry: dict) -> dict:
    required = {"id", "provider", "ranges"}
    missing = required - set(entry.keys())
    if missing:
        raise ValueError(f"Safelist entry missing fields: {sorted(missing)}")

    validated_ranges = []
    for cidr in entry["ranges"]:
        ipaddress.ip_network(cidr, strict=False)
        validated_ranges.append(str(cidr))

    return {
        "id": entry["id"],
        "provider": entry["provider"],
        "ranges": validated_ranges,
        "direction": entry.get("direction", ["inbound"]),
        "actions": {
            "never_block": entry.get("actions", {}).get("never_block", True),
            "never_escalate": entry.get("actions", {}).get("never_escalate", True),
            "cap_severity": entry.get("actions", {}).get("cap_severity", "LOW"),
        },
        "source": entry.get("source", "client"),
        "notes": entry.get("notes", ""),
    }


class SafelistRegistry:
    def __init__(
        self,
        default_entries: list[dict],
        client_entries: Optional[list[dict]] = None,
        client_id: Optional[str] = None,
    ):
        self.client_id = client_id
        self._entries = self._merge(default_entries, client_entries or [])

    @classmethod
    def from_files(cls, client_id: Optional[str] = None) -> "SafelistRegistry":
        default_payload = json.loads(DEFAULT_SAFELIST_PATH.read_text(encoding="utf-8"))
        default_entries = default_payload.get("entries", [])

        client_entries = []
        if client_id:
            client_path = CLIENT_CONFIG_DIR / f"{client_id}_safelist.json"
            if client_path.exists():
                client_payload = json.loads(client_path.read_text(encoding="utf-8"))
                client_entries = client_payload.get("entries", [])

        return cls(default_entries, client_entries, client_id)

    @classmethod
    def for_client(cls, client_id: Optional[str] = None) -> "SafelistRegistry":
        return cls.from_files(client_id)

    @staticmethod
    def _merge(default_entries: list[dict], client_entries: list[dict]) -> dict[str, dict]:
        merged: dict[str, dict] = {}
        for entry in default_entries:
            validated = _validate_entry({**entry, "source": entry.get("source", "default")})
            merged[validated["id"]] = validated
        for entry in client_entries:
            validated = _validate_entry({**entry, "source": entry.get("source", "client")})
            merged[validated["id"]] = validated
        return merged

    def list_entries(self) -> list[dict]:
        return sorted(self._entries.values(), key=lambda item: item["provider"].lower())

    def table(self) -> list[dict]:
        rows = []
        for entry in self.list_entries():
            for cidr in entry["ranges"]:
                rows.append(
                    {
                        "entry_id": entry["id"],
                        "provider": entry["provider"],
                        "cidr": cidr,
                        "direction": entry["direction"],
                        "actions": entry["actions"],
                        "source": entry["source"],
                        "notes": entry["notes"],
                    }
                )
        return rows

    def match_ip(self, ip_address: str, direction: str = "inbound") -> Optional[dict]:
        try:
            ip_obj = ipaddress.ip_address(ip_address)
        except ValueError:
            return None

        best_match = None
        best_prefix = -1

        for entry in self._entries.values():
            if direction not in entry.get("direction", ["inbound"]):
                continue

            for network in entry["ranges"]:
                network_obj = ipaddress.ip_network(network, strict=False)
                if ip_obj in network_obj and network_obj.prefixlen > best_prefix:
                    best_prefix = network_obj.prefixlen
                    best_match = {
                        "entry_id": entry["id"],
                        "provider": entry["provider"],
                        "matched_range": str(network_obj),
                        "actions": entry["actions"],
                        "source": entry["source"],
                    }

        return best_match

    def add_client_entry(self, entry: dict, persist: bool = True) -> dict:
        if not self.client_id:
            raise ValueError("client_id is required to add client safelist entries")

        validated = _validate_entry({**entry, "source": "client"})
        self._entries[validated["id"]] = validated

        if persist:
            self._persist_client_entries()

        return validated

    def remove_client_entry(self, entry_id: str, persist: bool = True) -> bool:
        if not self.client_id:
            raise ValueError("client_id is required to remove client safelist entries")

        entry = self._entries.get(entry_id)
        if not entry or entry.get("source") != "client":
            return False

        del self._entries[entry_id]

        if persist:
            self._persist_client_entries()

        return True

    def _persist_client_entries(self) -> None:
        CLIENT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        client_path = CLIENT_CONFIG_DIR / f"{self.client_id}_safelist.json"
        client_entries = [
            entry for entry in self._entries.values() if entry.get("source") == "client"
        ]
        payload = {
            "client_id": self.client_id,
            "description": "Client-specific safelist entries merged on top of defaults.",
            "entries": client_entries,
        }
        client_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    @staticmethod
    def cap_severity(current: str, cap: str) -> str:
        if SEVERITY_RANK.get(current, 0) > SEVERITY_RANK.get(cap, 0):
            return cap
        return current
