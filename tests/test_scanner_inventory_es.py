"""Tests for scanner-inventory Elasticsearch sync."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from scanner_lite.storage.inventory_es_store import ScannerInventoryEsStore


class ScannerInventoryEsStoreTests(unittest.TestCase):
    def test_sync_from_publish_indexes_classifiable_ranges(self) -> None:
        client = MagicMock()
        client.index_document.return_value = {"result": "created"}
        store = ScannerInventoryEsStore(client=client)

        payload = {
            "meta": {"version": 7, "refreshed_at": "2026-06-22T12:00:00+00:00"},
            "csv_rows": [
                {
                    "vendor": "Censys",
                    "scanner_type": "internet_measurement",
                    "cidr": "162.142.125.0/24",
                    "source_url": "https://docs.censys.com",
                    "last_verified": "2026-06",
                    "confidence": "high",
                },
                {
                    "vendor": "FOFA",
                    "scanner_type": "internet_scanning",
                    "cidr": "",
                    "source_url": "https://fofa.info",
                    "last_verified": "2026-06",
                    "confidence": "dynamic",
                },
            ],
            "feed_snapshots": [
                {
                    "vendor": "BinaryEdge",
                    "scanner_type": "internet_scanning",
                    "source_url": "https://api.binaryedge.io/v1/minions",
                    "last_verified": "2026-06",
                    "confidence": "medium",
                    "refreshed_at": "2026-06-22T11:00:00+00:00",
                    "cidrs": ["3.24.125.137/32"],
                }
            ],
        }

        result = store.sync_from_publish(payload)
        self.assertEqual(result["indexed"], 2)
        self.assertEqual(result["inventory_version"], 7)
        self.assertEqual(client.index_document.call_count, 2)

        first_doc = client.index_document.call_args_list[0][0][1]
        self.assertEqual(first_doc["source"], "csv")
        second_doc = client.index_document.call_args_list[1][0][1]
        self.assertEqual(second_doc["source"], "feed_snapshot")
        self.assertEqual(second_doc["vendor"], "BinaryEdge")

    def test_count_ranges_queries_version(self) -> None:
        client = MagicMock()
        client.request.return_value = {"count": 42}
        store = ScannerInventoryEsStore(client=client)
        count = store.count_ranges(inventory_version=7)
        self.assertEqual(count, 42)
        body = client.request.call_args[0][2]
        self.assertEqual(body["query"]["term"]["inventory_version"], 7)


if __name__ == "__main__":
    unittest.main()
