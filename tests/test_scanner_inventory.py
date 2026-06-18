import os
import tempfile
import unittest


class ScannerInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("STINGAR_LOCAL_CACHE_PATH", tempfile.mktemp(suffix=".sqlite3"))

    def test_classify_cortex_xpanse_from_inventory(self):
        from threat_intel.scanners import ScannerRegistry, classify_known_scanner

        registry = ScannerRegistry.for_client()
        result = classify_known_scanner("198.235.24.10", registry=registry)

        self.assertTrue(result["is_known_scanner"])
        self.assertEqual(result["company"], "Palo Alto Networks Cortex Xpanse")
        self.assertEqual(result["matched_range"], "198.235.24.0/24")
        self.assertEqual(result["confidence"], "high")
        self.assertIn("paloaltonetworks.com", result["source_url"])

    def test_classify_unknown_ip(self):
        from threat_intel.scanners import classify_known_scanner

        result = classify_known_scanner("203.0.113.42")
        self.assertFalse(result["is_known_scanner"])
        self.assertEqual(result["classification"], "not_known_scanner")

    def test_inventory_includes_pending_vendors(self):
        from threat_intel.scanners import list_scanner_inventory

        inventory = list_scanner_inventory()
        vendors = {row["vendor"] for row in inventory["inventory"]}

        self.assertIn("Shodan", vendors)
        self.assertIn("Rapid7 Project Sonar", vendors)
        self.assertIn("Palo Alto Networks Cortex Xpanse", vendors)
        self.assertGreater(inventory["classifiable_range_count"], 0)
        self.assertIn("Shodan", inventory["pending_or_dynamic_vendors"])

    def test_longest_prefix_wins(self):
        from threat_intel.scanners import ScannerRegistry

        registry = ScannerRegistry(
            default_scanners=[
                {
                    "id": "test-wide",
                    "company": "Test Wide Scanner",
                    "category": "internet_scanning",
                    "ranges": ["10.0.0.0/8"],
                    "range_metadata": {
                        "10.0.0.0/8": {
                            "source_url": "https://example.test/wide",
                            "last_verified": "2026-06",
                            "confidence": "high",
                            "scanner_type": "internet_scanning",
                        }
                    },
                },
                {
                    "id": "test-narrow",
                    "company": "Test Narrow Scanner",
                    "category": "internet_scanning",
                    "ranges": ["10.0.0.0/24"],
                    "range_metadata": {
                        "10.0.0.0/24": {
                            "source_url": "https://example.test/narrow",
                            "last_verified": "2026-06",
                            "confidence": "high",
                            "scanner_type": "internet_scanning",
                        }
                    },
                },
            ]
        )

        result = registry.classify_ip("10.0.0.42")
        self.assertTrue(result["is_known_scanner"])
        self.assertEqual(result["scanner_id"], "test-narrow")
        self.assertEqual(result["matched_range"], "10.0.0.0/24")


if __name__ == "__main__":
    unittest.main()
