"""Tests for Redis-backed scanner inventory store."""

from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import fakeredis

from threat_intel.scanner_redis_store import ScannerRedisStore


class ScannerRedisStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = ScannerRedisStore(redis_url="redis://fake", key_prefix="scanner")
        self.store._redis = fakeredis.FakeRedis(decode_responses=True)

    def test_publish_load_round_trip(self) -> None:
        csv_rows = [
            {
                "vendor": "Censys",
                "scanner_type": "internet_measurement",
                "cidr": "162.142.125.0/24",
                "source_url": "https://docs.censys.com/docs/opt-out-of-data-collection",
                "last_verified": "2026-06",
                "confidence": "high",
            }
        ]
        feed_snapshots = [
            {
                "vendor": "BinaryEdge",
                "scanner_type": "internet_scanning",
                "source_url": "https://api.binaryedge.io/v1/minions",
                "last_verified": "2026-06",
                "confidence": "medium",
                "cidrs": ["3.24.125.137/32"],
            }
        ]
        compiled = {
            "scanner-lite": [
                {
                    "id": "censys",
                    "company": "Censys",
                    "category": "internet_measurement",
                    "classification": "known_scanner",
                    "default_severity": "LOW",
                    "source": "inventory",
                    "ranges": ["162.142.125.0/24"],
                    "notes": "test",
                    "range_metadata": {},
                }
            ]
        }

        meta = self.store.publish_inventory(csv_rows, feed_snapshots, compiled)
        self.assertEqual(meta["version"], 1)
        self.assertEqual(self.store.load_csv_rows(), csv_rows)
        self.assertEqual(self.store.load_meta()["version"], 1)
        self.assertEqual(len(self.store.load_all_feed_snapshots()), 1)
        self.assertEqual(len(self.store.load_compiled_registry("scanner-lite")), 1)

    def test_export_to_files(self) -> None:
        import tempfile
        from pathlib import Path

        csv_rows = [
            {
                "vendor": "Censys",
                "scanner_type": "internet_measurement",
                "cidr": "162.142.125.0/24",
                "source_url": "https://example.com",
                "last_verified": "2026-06",
                "confidence": "high",
            }
        ]
        self.store.publish_inventory(csv_rows, [], {"scanner-lite": []})

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = Path(tmpdir) / "inventory.csv"
            feed_dir = Path(tmpdir) / "feeds"
            stats = self.store.export_to_files(csv_path, feed_dir)
            self.assertEqual(stats["csv_rows"], 1)
            self.assertTrue(csv_path.exists())
            exported = csv_path.read_text(encoding="utf-8")
            self.assertIn("Censys", exported)

    def test_classify_from_compiled_registry(self) -> None:
        from threat_intel.scanners import ScannerRegistry, configure_scanners

        csv_rows = [
            {
                "vendor": "Palo Alto Networks Cortex Xpanse",
                "scanner_type": "attack_surface_scanning",
                "cidr": "198.235.24.0/24",
                "source_url": "https://docs-cortex.paloaltonetworks.com",
                "last_verified": "2026-06",
                "confidence": "high",
            }
        ]
        feed_snapshots = []
        compiled_entries = [
            {
                "id": "palo-alto-networks-cortex-xpanse",
                "company": "Palo Alto Networks Cortex Xpanse",
                "category": "attack_surface_scanning",
                "classification": "known_scanner",
                "default_severity": "LOW",
                "source": "inventory",
                "ranges": ["198.235.24.0/24"],
                "notes": "test",
                "range_metadata": {
                    "198.235.24.0/24": {
                        "source_url": "https://docs-cortex.paloaltonetworks.com",
                        "last_verified": "2026-06",
                        "confidence": "high",
                        "scanner_type": "attack_surface_scanning",
                    }
                },
            }
        ]
        self.store.publish_inventory(csv_rows, feed_snapshots, {"scanner-lite": compiled_entries})

        os.environ["SCANNER_INVENTORY_BACKEND"] = "redis"
        with patch("threat_intel.scanner_redis_store.get_scanner_redis_store", return_value=self.store):
            registry = ScannerRegistry.from_redis("scanner-lite")
        configure_scanners(registry)
        result = registry.classify_ip("198.235.24.10")
        self.assertTrue(result["is_known_scanner"])
        self.assertEqual(result["company"], "Palo Alto Networks Cortex Xpanse")
        os.environ["SCANNER_INVENTORY_BACKEND"] = "file"


if __name__ == "__main__":
    unittest.main()
