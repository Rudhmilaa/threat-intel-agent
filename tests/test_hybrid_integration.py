"""Integration tests for hybrid local-global enrichment."""

from __future__ import annotations

import os
import tempfile
from unittest import TestCase, mock

os.environ["STINGAR_STORAGE_BACKEND"] = "sqlite"
os.environ.setdefault("STINGAR_LOCAL_CACHE_PATH", tempfile.mktemp(suffix="_local_cache.db"))
os.environ.setdefault("STINGAR_SYNC_QUEUE_PATH", tempfile.mktemp(suffix="_sync_queue.db"))
os.environ.setdefault("CENTRAL_CACHE_SQLITE_PATH", tempfile.mktemp(suffix="_global_cache.db"))


class HybridEnrichmentTests(TestCase):
    def setUp(self):
        self.client_id = "example-stingar-01"
        self.sample_event = {
            "source_ip": "198.235.24.10",
            "destination_ip": "10.0.0.25",
            "destination_port": 8080,
            "attack_type": "service_probe",
            "protocol": "http",
            "honeypot_type": "web",
        }

    def test_local_enrichment_returns_taxonomy(self):
        from threat_intel.local_pipeline import enrich_events_locally

        result = enrich_events_locally(
            [self.sample_event],
            self.client_id,
            new_ips=["198.235.24.10"],
        )
        self.assertEqual(result["enrichment_source"], "local")
        self.assertTrue(result["incident_clusters"])
        self.assertIn("taxonomy", result["incident_clusters"][0])
        doc = result["enriched_documents"][0]
        self.assertIn("taxonomy", doc)
        self.assertTrue(doc["taxonomy"]["tags"])

    def test_safelist_caps_severity(self):
        from threat_intel.policy_engine import apply_policy_to_summary
        from threat_intel.safelist import SafelistRegistry

        match = SafelistRegistry.for_client(self.client_id).match_ip("198.235.24.10")
        self.assertIsNotNone(match)

        summary = {
            "severity": {"severity": "HIGH"},
            "investigation": {},
        }
        updated = apply_policy_to_summary(summary, "198.235.24.10", client_id=self.client_id)
        self.assertIn("policy:safelisted", updated.get("policy_tags", []))

    def test_sharing_blocks_private_destination(self):
        from threat_intel.policy_engine import evaluate_shareability

        doc = {
            "destination": {"ip": "10.0.0.25"},
            "investigation": {"classification": "known_scanner_high_noise"},
        }
        decision = evaluate_shareability(doc, self.client_id)
        self.assertFalse(decision["allowed"])
        self.assertIn("destination", decision["reason"].lower())

    def test_hybrid_client_skips_sync_when_offline(self):
        from stingar.client import HybridEnrichmentClient

        public_dest_event = {
            **self.sample_event,
            "destination_ip": "203.0.113.50",
        }
        client = HybridEnrichmentClient(client_id=self.client_id, central_url="")
        result = client.process_events([public_dest_event])
        self.assertEqual(result["sync"]["sync_status"], "skipped")
        self.assertEqual(result["enrichment_source"], "local")

    def test_hybrid_client_blocks_sync_for_private_destination(self):
        from stingar.client import HybridEnrichmentClient

        client = HybridEnrichmentClient(
            client_id=self.client_id,
            central_url="http://127.0.0.1:8080",
        )
        with mock.patch.object(client, "_attempt_sync") as mock_sync:
            result = client.process_events([self.sample_event])
            mock_sync.assert_not_called()
        self.assertEqual(result["sync"]["sync_status"], "blocked")

    def test_llm_gateway_rejects_non_joined_client(self):
        from fastapi import HTTPException

        from central.llm_gateway import investigate_with_llm

        with self.assertRaises(HTTPException) as ctx:
            investigate_with_llm(self.client_id, "203.0.113.42", "ip_address")
        self.assertEqual(ctx.exception.status_code, 403)


if __name__ == "__main__":
    import unittest

    unittest.main()
