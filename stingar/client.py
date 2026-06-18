"""STINGAR-side hybrid client: local enrichment first, optional global sync."""

from __future__ import annotations

import json
import os
from typing import Optional

import requests
from dotenv import load_dotenv

from stingar.sync_queue import SyncQueue
from threat_intel.local_pipeline import enrich_events_locally
from threat_intel.policy_engine import evaluate_shareability
from threat_intel.sharing_policy import load_sharing_policy
from threat_intel.storage import get_intelligence_cache

load_dotenv()


class HybridEnrichmentClient:
    """
    Hybrid STINGAR enrichment client.

    Always enriches locally first. Optionally syncs sanitized payloads to central
    when online and allowed by sharing policy.

    IP deduplication uses the intelligence cache (intel-summaries / ES) — not a
    separate seen-IP JSON file.
    """

    def __init__(
        self,
        client_id: str,
        central_url: Optional[str] = None,
        sensor_id: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 30,
        sync_queue: Optional[SyncQueue] = None,
    ):
        self.client_id = client_id
        self.central_url = (central_url or os.getenv("CENTRAL_ENRICHMENT_URL", "")).rstrip("/")
        self.sensor_id = sensor_id
        self.timeout = timeout
        self.api_key = api_key or os.getenv("CENTRAL_API_KEY")
        self.deployment_mode = os.getenv(
            "STINGAR_DEPLOYMENT_MODE",
            load_sharing_policy(client_id).get("deployment_mode", "hybrid"),
        )
        self.sync_queue = sync_queue or SyncQueue()

    def _headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def extract_source_ips(self, events: list[dict]) -> list[str]:
        return sorted({event.get("source_ip") for event in events if event.get("source_ip")})

    def filter_new_ips(self, ip_addresses: list[str]) -> list[str]:
        return get_intelligence_cache().filter_new_ips(self.client_id, ip_addresses)

    def _build_sync_payload(self, local_result: dict, shareable_docs: list[dict]) -> dict:
        return {
            "client_id": self.client_id,
            "sensor_id": self.sensor_id,
            "enriched_documents": shareable_docs,
            "batch_summary": local_result.get("batch_summary"),
            "incident_clusters": local_result.get("incident_clusters"),
            "prioritized_incidents": local_result.get("prioritized_incidents"),
            "enrichment_stats": local_result.get("enrichment_stats"),
            "enrichment_source": "local",
        }

    def _attempt_sync(self, payload: dict) -> dict:
        if not self.central_url or self.deployment_mode == "local_only":
            return {"sync_status": "skipped", "reason": "local_only or no central URL"}

        try:
            response = requests.post(
                f"{self.central_url}/api/v1/sync/events",
                json=payload,
                headers=self._headers(),
                timeout=self.timeout,
            )
            response.raise_for_status()
            body = response.json()
            return {"sync_status": "synced", "central_response": body}
        except Exception as error:
            queue_id = self.sync_queue.enqueue(self.client_id, payload)
            return {
                "sync_status": "queued",
                "reason": str(error),
                "queue_id": queue_id,
            }

    def process_events(self, events: list[dict]) -> dict:
        source_ips = self.extract_source_ips(events)
        new_ips = self.filter_new_ips(source_ips)

        local_result = enrich_events_locally(
            events=events,
            client_id=self.client_id,
            new_ips=new_ips,
            auto_detect_new_ips=False,
        )

        shareable_docs = []
        blocked_docs = 0
        for document in local_result.get("enriched_documents", []):
            decision = evaluate_shareability(document, self.client_id)
            if decision["allowed"]:
                shareable_docs.append(decision["sanitized_document"])
            else:
                blocked_docs += 1

        sync_result = {"sync_status": "blocked", "blocked_documents": blocked_docs}
        if shareable_docs and self.deployment_mode != "local_only":
            payload = self._build_sync_payload(local_result, shareable_docs)
            sync_result = self._attempt_sync(payload)
        elif blocked_docs and not shareable_docs:
            sync_result = {
                "sync_status": "blocked",
                "reason": "all documents blocked by sharing policy",
                "blocked_documents": blocked_docs,
            }

        local_result["local_stats"] = {
            "source_ips_in_batch": len(source_ips),
            "new_ips_enriched_locally": len(new_ips),
            "cached_ips_locally": len(source_ips) - len(new_ips),
        }
        local_result["sync"] = sync_result
        local_result["deployment_mode"] = self.deployment_mode

        es_stats = local_result.get("es_stats") or {}
        if es_stats.get("failed"):
            local_result["storage_warnings"] = es_stats.get("errors", [])

        return local_result

    def enrich_new_ips_only(self, ip_addresses: list[str]) -> dict:
        new_ips = self.filter_new_ips(ip_addresses)
        events = [
            {
                "source_ip": ip,
                "destination_ip": "0.0.0.0",
                "destination_port": 0,
                "attack_type": "ip_lookup",
            }
            for ip in new_ips
        ]
        if not events:
            return {
                "client_id": self.client_id,
                "summaries": {},
                "local_stats": {
                    "new_ips_enriched_locally": 0,
                    "cached_ips_locally": len(ip_addresses),
                },
            }

        result = self.process_events(events)
        summaries = {}
        for document in result.get("enriched_documents", []):
            source_ip = document.get("source", {}).get("ip")
            if source_ip:
                summaries[source_ip] = {
                    "indicator": source_ip,
                    "severity": document.get("threat", {}),
                    "investigation": document.get("investigation", {}),
                }

        return {
            "client_id": self.client_id,
            "summaries": summaries,
            "local_stats": result.get("local_stats"),
            "sync": result.get("sync"),
        }

    def get_scanner_table(self) -> dict:
        if not self.central_url:
            from threat_intel.scanners import ScannerRegistry

            registry = ScannerRegistry.for_client(self.client_id)
            return {"client_id": self.client_id, "table": registry.scanner_table()}

        response = requests.get(
            f"{self.central_url}/api/v1/scanners/table",
            params={"client_id": self.client_id},
            headers=self._headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def get_safelist_table(self) -> dict:
        if not self.central_url:
            from threat_intel.safelist import SafelistRegistry

            registry = SafelistRegistry.for_client(self.client_id)
            return {"client_id": self.client_id, "table": registry.table()}

        response = requests.get(
            f"{self.central_url}/api/v1/safelist/table",
            params={"client_id": self.client_id},
            headers=self._headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()


# Backward-compatible alias
StingarEnrichmentClient = HybridEnrichmentClient


def main():
    import argparse

    parser = argparse.ArgumentParser(description="STINGAR hybrid enrichment client demo")
    parser.add_argument("--central-url", default=os.getenv("CENTRAL_ENRICHMENT_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--client-id", default=os.getenv("STINGAR_CLIENT_ID", "example-stingar-01"))
    parser.add_argument("--sensor-id", default=os.getenv("STINGAR_SENSOR_ID", "stingar-demo-sensor-01"))
    args = parser.parse_args()

    client = HybridEnrichmentClient(
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

    print("Running hybrid local-first enrichment...")
    result = client.process_events(sample_events)
    print(json.dumps(result.get("local_stats"), indent=2))
    print(json.dumps(result.get("enrichment_stats"), indent=2))
    print(json.dumps(result.get("sync"), indent=2))
    print(f"Prioritized incidents: {len(result.get('prioritized_incidents', []))}")


if __name__ == "__main__":
    main()
