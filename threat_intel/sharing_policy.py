"""Client sharing and deployment policy configuration."""

from __future__ import annotations

import ipaddress
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CLIENT_CONFIG_DIR = PROJECT_ROOT / "config" / "clients"

DEFAULT_POLICY = {
    "deployment_mode": "hybrid",
    "global_joined": False,
    "share_events": False,
    "share_enriched_documents": True,
    "share_mode": "sanitized",
    "never_share_fields": [
        "destination.ip",
        "event.original",
        "stingar.sensor_id",
    ],
    "never_share_if_tags": ["internal", "student_network"],
    "never_share_classifications": ["confirmed_malicious_infrastructure"],
    "never_share_destination_cidrs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
}


def load_sharing_policy(client_id: str) -> dict:
    policy = deepcopy(DEFAULT_POLICY)
    policy["client_id"] = client_id

    policy_path = CLIENT_CONFIG_DIR / f"{client_id}_sharing_policy.json"
    if policy_path.exists():
        payload = json.loads(policy_path.read_text(encoding="utf-8"))
        policy.update({key: value for key, value in payload.items() if key != "client_id"})

    return policy


def save_sharing_policy(client_id: str, updates: dict) -> dict:
    policy = load_sharing_policy(client_id)
    policy.update(updates)
    policy["client_id"] = client_id

    CLIENT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    policy_path = CLIENT_CONFIG_DIR / f"{client_id}_sharing_policy.json"
    policy_path.write_text(json.dumps(policy, indent=2) + "\n", encoding="utf-8")
    return policy


def _get_nested_value(data: dict, dotted_path: str) -> Any:
    current: Any = data
    for part in dotted_path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _delete_nested_value(data: dict, dotted_path: str) -> None:
    parts = dotted_path.split(".")
    current = data
    for part in parts[:-1]:
        if not isinstance(current, dict) or part not in current:
            return
        current = current[part]
    if isinstance(current, dict):
        current.pop(parts[-1], None)


def destination_in_blocked_cidr(destination_ip: Optional[str], cidrs: list[str]) -> bool:
    if not destination_ip:
        return False

    try:
        ip_obj = ipaddress.ip_address(destination_ip)
    except ValueError:
        return False

    for cidr in cidrs:
        if ip_obj in ipaddress.ip_network(cidr, strict=False):
            return True

    return False
