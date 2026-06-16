"""STINGAR-side client that tracks seen IPs and forwards new work to central."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()


class SeenIPStore:
    """Persistent local store of source IPs already submitted to central."""

    def __init__(self, store_path: Path | str):
        self.store_path = Path(store_path)
        self._data = self._load()

    def _load(self) -> dict:
        if not self.store_path.exists():
            return {"seen_ips": {}}

        return json.loads(self.store_path.read_text(encoding="utf-8"))

    def _save(self) -> None:
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.store_path.write_text(json.dumps(self._data, indent=2) + "\n", encoding="utf-8")

    def has_seen(self, ip_address: str) -> bool:
        return ip_address in self._data.get("seen_ips", {})

    def mark_seen(self, ip_address: str) -> None:
        self._data.setdefault("seen_ips", {})[ip_address] = {
            "first_seen_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save()

    def mark_many_seen(self, ip_addresses: list[str]) -> None:
        for ip_address in ip_addresses:
            if ip_address:
                self.mark_seen(ip_address)

    def filter_new_ips(self, ip_addresses: list[str]) -> list[str]:
        return sorted({ip for ip in ip_addresses if ip and not self.has_seen(ip)})

    def list_seen_ips(self) -> list[str]:
        return sorted(self._data.get("seen_ips", {}).keys())


class StingarEnrichmentClient:
    """
    Runs on a STINGAR honeypot server.

    Workflow:
    1. Accept honeypot events locally
    2. Determine which source IPs are new
    3. Send events + new_ips to the central enrichment server
    4. Persist newly observed IPs locally so repeat traffic does not re-trigger enrichment
    """

    def __init__(
        self,
        central_url: str,
        client_id: str,
        sensor_id: Optional[str] = None,
        seen_ip_store_path: Optional[Path | str] = None,
        api_key: Optional[str] = None,
        timeout: int = 30,
    ):
        self.central_url = central_url.rstrip("/")
        self.client_id = client_id
        self.sensor_id = sensor_id
        self.timeout = timeout
        self.api_key = api_key or os.getenv("CENTRAL_API_KEY")

        default_store = Path(os.getenv("STINGAR_SEEN_IP_STORE", ".stingar_seen_ips.json"))
        self.seen_store = SeenIPStore(seen_ip_store_path or default_store)

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def extract_source_ips(self, events: list[dict]) -> list[str]:
        return sorted({event.get("source_ip") for event in events if event.get("source_ip")})

    def process_events(self, events: list[dict]) -> dict:
        source_ips = self.extract_source_ips(events)
        new_ips = self.seen_store.filter_new_ips(source_ips)

        payload = {
            "client_id": self.client_id,
            "sensor_id": self.sensor_id,
            "events": events,
            "new_ips": new_ips,
        }

        response = requests.post(
            f"{self.central_url}/api/v1/enrich/events",
            json=payload,
            headers=self._headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        result = response.json()

        self.seen_store.mark_many_seen(source_ips)
        result["local_stats"] = {
            "source_ips_in_batch": len(source_ips),
            "new_ips_forwarded": len(new_ips),
            "cached_ips_locally": len(source_ips) - len(new_ips),
        }
        return result

    def enrich_new_ips_only(self, ip_addresses: list[str]) -> dict:
        new_ips = self.seen_store.filter_new_ips(ip_addresses)
        if not new_ips:
            return {
                "client_id": self.client_id,
                "summaries": {},
                "local_stats": {
                    "new_ips_forwarded": 0,
                    "cached_ips_locally": len(ip_addresses),
                },
            }

        response = requests.post(
            f"{self.central_url}/api/v1/enrich/ips",
            json={"client_id": self.client_id, "ip_addresses": new_ips},
            headers=self._headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        result = response.json()
        self.seen_store.mark_many_seen(new_ips)
        result["local_stats"] = {
            "new_ips_forwarded": len(new_ips),
            "cached_ips_locally": len(ip_addresses) - len(new_ips),
        }
        return result

    def get_scanner_table(self) -> dict:
        response = requests.get(
            f"{self.central_url}/api/v1/scanners/table",
            params={"client_id": self.client_id},
            headers=self._headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def add_client_scanner(self, scanner_entry: dict) -> dict:
        response = requests.post(
            f"{self.central_url}/api/v1/scanners",
            json={"client_id": self.client_id, "scanner": scanner_entry},
            headers=self._headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()


def main():
    import argparse

    parser = argparse.ArgumentParser(description="STINGAR enrichment client demo")
    parser.add_argument("--central-url", default=os.getenv("CENTRAL_ENRICHMENT_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--client-id", default=os.getenv("STINGAR_CLIENT_ID", "example-stingar-01"))
    parser.add_argument("--sensor-id", default=os.getenv("STINGAR_SENSOR_ID", "stingar-demo-sensor-01"))
    args = parser.parse_args()

    client = StingarEnrichmentClient(
        central_url=args.central_url,
        client_id=args.client_id,
        sensor_id=args.sensor_id,
    )

    sample_events = [
        {
            "source_ip": "203.0.113.42",
            "source_port": 55231,
            "destination_ip": "10.0.0.25",
            "destination_port": 22,
            "protocol": "ssh",
            "transport": "tcp",
            "sensor_id": args.sensor_id,
            "honeypot_type": "cowrie",
            "attack_type": "ssh_bruteforce",
        },
        {
            "source_ip": "198.235.24.10",
            "source_port": 49530,
            "destination_ip": "10.0.0.25",
            "destination_port": 8080,
            "protocol": "http",
            "transport": "tcp",
            "sensor_id": args.sensor_id,
            "honeypot_type": "web_honeypot",
            "attack_type": "service_probe",
        },
    ]

    print("Submitting batch to central enrichment server...")
    result = client.process_events(sample_events)
    print(json.dumps(result.get("local_stats"), indent=2))
    print(json.dumps(result.get("enrichment_stats"), indent=2))
    print(f"Prioritized incidents: {len(result.get('prioritized_incidents', []))}")


if __name__ == "__main__":
    main()
