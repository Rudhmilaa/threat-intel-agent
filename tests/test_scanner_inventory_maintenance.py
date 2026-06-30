import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from threat_intel.scanner_inventory_maintenance import (
    FeedResult,
    fetch_censys_feed,
    fetch_xpanse_feed,
    merge_inventory_rows,
    refresh_scanner_inventory,
    write_scanner_inventory,
)
from threat_intel.scanners import load_scanner_inventory


class ScannerInventoryMaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["SCANNER_INVENTORY_BACKEND"] = "file"

    def test_merge_inventory_replaces_managed_vendor_rows(self):
        existing = [
            {
                "vendor": "Censys",
                "scanner_type": "internet_measurement",
                "cidr": "1.2.3.0/24",
                "source_url": "https://old.example",
                "last_verified": "2020-01",
                "confidence": "high",
            },
            {
                "vendor": "The Shadowserver Foundation",
                "scanner_type": "internet_measurement",
                "cidr": "64.62.128.0/21",
                "source_url": "https://shadowserver.org",
                "last_verified": "2026-06",
                "confidence": "medium",
            },
        ]
        feeds = [
            FeedResult(
                vendor="Censys",
                scanner_type="internet_measurement",
                source_url="https://docs.censys.com/docs/opt-out-of-data-collection",
                confidence="high",
                cidrs=["162.142.125.0/24"],
            )
        ]

        merged, stats, _snapshots = merge_inventory_rows(existing, feeds, [], "2026-06")
        censys_rows = [row for row in merged if row["vendor"] == "Censys"]
        shadow_rows = [row for row in merged if row["vendor"] == "The Shadowserver Foundation"]

        self.assertEqual(len(censys_rows), 1)
        self.assertEqual(censys_rows[0]["cidr"], "162.142.125.0/24")
        self.assertEqual(len(shadow_rows), 1)
        self.assertEqual(stats["updated"], 1)

    def test_refresh_writes_inventory_and_reloads_registry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "known_scanner_inventory.csv"
            write_scanner_inventory(
                [
                    {
                        "vendor": "Censys",
                        "scanner_type": "internet_measurement",
                        "cidr": "1.2.3.0/24",
                        "source_url": "https://old.example",
                        "last_verified": "2020-01",
                        "confidence": "high",
                    }
                ],
                inventory_path,
            )

            mock_feed = FeedResult(
                vendor="Censys",
                scanner_type="internet_measurement",
                source_url="https://docs.censys.com/docs/opt-out-of-data-collection",
                confidence="high",
                cidrs=["162.142.125.0/24", "167.94.138.0/24"],
            )

            with patch(
                "threat_intel.scanner_inventory_maintenance.AUTO_MANAGED_FEEDS",
                [lambda: mock_feed],
            ):
                report = refresh_scanner_inventory(
                    inventory_path=inventory_path,
                    write_changes=True,
                    reload_registry=True,
                    feeds=[lambda: mock_feed],
                )

            rows = load_scanner_inventory(inventory_path)
            censys_cidrs = sorted(row["cidr"] for row in rows if row["vendor"] == "Censys")
            self.assertEqual(censys_cidrs, ["162.142.125.0/24", "167.94.138.0/24"])
            self.assertEqual(report.summary["row_count_after"], 2)

    def test_refresh_publishes_to_redis_and_syncs_es(self):
        import fakeredis
        from threat_intel.scanner_redis_store import ScannerRedisStore

        os.environ["SCANNER_INVENTORY_BACKEND"] = "redis"
        store = ScannerRedisStore(redis_url="redis://fake", key_prefix="scanner")
        store._redis = fakeredis.FakeRedis(decode_responses=True)

        mock_feed = FeedResult(
            vendor="Censys",
            scanner_type="internet_measurement",
            source_url="https://docs.censys.com/docs/opt-out-of-data-collection",
            confidence="high",
            cidrs=["162.142.125.0/24"],
        )

        with patch("threat_intel.scanner_redis_store.get_scanner_redis_store", return_value=store):
            with patch(
                "scanner_lite.storage.inventory_es_store.ScannerInventoryEsStore"
            ) as es_cls:
                es_store = es_cls.return_value
                es_store.sync_from_publish.return_value = {
                    "indexed": 1,
                    "failed": 0,
                    "index": "scanner-inventory-2026-06-22",
                    "inventory_version": 1,
                    "errors": [],
                }
                report = refresh_scanner_inventory(
                    write_changes=True,
                    reload_registry=False,
                    feeds=[lambda: mock_feed],
                    skip_es=False,
                    seed_from_files=True,
                )

        self.assertEqual(report.summary["inventory_backend"], "redis")
        self.assertGreaterEqual(store.load_meta()["version"], 1)
        censys_rows = [row for row in store.load_csv_rows() if row["vendor"] == "Censys"]
        self.assertEqual(len(censys_rows), 1)
        self.assertEqual(censys_rows[0]["cidr"], "162.142.125.0/24")
        es_store.sync_from_publish.assert_called_once()
        report_dict = report.to_dict()
        self.assertEqual(report_dict["inventory_backend"], "redis")
        self.assertIsNotNone(report_dict.get("inventory_version"))

    def test_refresh_updates_redis_es_meta_after_sync(self):
        import fakeredis
        from threat_intel.scanner_redis_store import ScannerRedisStore

        os.environ["SCANNER_INVENTORY_BACKEND"] = "redis"
        store = ScannerRedisStore(redis_url="redis://fake", key_prefix="scanner")
        store._redis = fakeredis.FakeRedis(decode_responses=True)

        mock_feed = FeedResult(
            vendor="Censys",
            scanner_type="internet_measurement",
            source_url="https://docs.censys.com/docs/opt-out-of-data-collection",
            confidence="high",
            cidrs=["162.142.125.0/24"],
        )

        with patch("threat_intel.scanner_redis_store.get_scanner_redis_store", return_value=store):
            with patch(
                "scanner_lite.storage.inventory_es_store.ScannerInventoryEsStore"
            ) as es_cls:
                es_store = es_cls.return_value
                es_store.sync_from_publish.return_value = {
                    "indexed": 42,
                    "failed": 0,
                    "index": "scanner-inventory-2026-06-29",
                    "inventory_version": 3,
                    "errors": [],
                }
                report = refresh_scanner_inventory(
                    write_changes=True,
                    reload_registry=False,
                    feeds=[lambda: mock_feed],
                    skip_es=False,
                    seed_from_files=True,
                )

        meta = store.load_meta()
        self.assertEqual(meta["es_doc_count"], 42)
        self.assertEqual(meta["es_sync_index"], "scanner-inventory-2026-06-29")
        report_dict = report.to_dict()
        self.assertEqual(report_dict["es_sync"]["indexed"], 42)
        self.assertEqual(report_dict["inventory_backend"], "redis")

    def test_refresh_export_files_writes_csv_and_feed_json(self):
        import fakeredis
        from threat_intel.scanner_redis_store import ScannerRedisStore

        os.environ["SCANNER_INVENTORY_BACKEND"] = "redis"
        store = ScannerRedisStore(redis_url="redis://fake", key_prefix="scanner")
        store._redis = fakeredis.FakeRedis(decode_responses=True)

        mock_feed = FeedResult(
            vendor="Censys",
            scanner_type="internet_measurement",
            source_url="https://docs.censys.com/docs/opt-out-of-data-collection",
            confidence="high",
            cidrs=["162.142.125.0/24"],
        )
        feed_snapshot = FeedResult(
            vendor="BinaryEdge",
            scanner_type="internet_scanning",
            source_url="https://api.binaryedge.io/v1/minions",
            confidence="medium",
            cidrs=["3.24.125.137/32"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            inventory_path = Path(tmpdir) / "known_scanner_inventory.csv"
            feed_dir = Path(tmpdir) / "feeds"

            with patch("threat_intel.scanner_redis_store.get_scanner_redis_store", return_value=store):
                with patch(
                    "scanner_lite.storage.inventory_es_store.ScannerInventoryEsStore"
                ) as es_cls:
                    es_cls.return_value.sync_from_publish.return_value = {
                        "indexed": 1,
                        "failed": 0,
                        "index": "scanner-inventory-2026-06-22",
                        "inventory_version": 1,
                        "errors": [],
                    }
                    with patch(
                        "threat_intel.scanner_inventory_maintenance.SCANNER_FEED_SNAPSHOT_DIR",
                        feed_dir,
                    ):
                        report = refresh_scanner_inventory(
                            inventory_path=inventory_path,
                            write_changes=True,
                            reload_registry=False,
                            feeds=[lambda: mock_feed, lambda: feed_snapshot],
                            skip_es=True,
                            export_files=True,
                            seed_from_files=True,
                        )

            self.assertTrue(inventory_path.exists())
            rows = load_scanner_inventory(inventory_path)
            censys_rows = [row for row in rows if row["vendor"] == "Censys"]
            self.assertEqual(len(censys_rows), 1)
            self.assertEqual(censys_rows[0]["cidr"], "162.142.125.0/24")

            feed_files = list(feed_dir.glob("*.json"))
            self.assertGreaterEqual(len(feed_files), 1)
            self.assertIn("export_files", report.summary)
            self.assertEqual(report.summary["export_files"]["csv_rows"], len(rows))

    @patch("threat_intel.scanner_inventory_maintenance._fetch_text")
    def test_fetch_xpanse_feed_uses_documented_fallback(self, mock_fetch):
        mock_fetch.return_value = "<html>Loading application...</html>"
        feed = fetch_xpanse_feed()
        self.assertEqual(feed.status, "ok")
        self.assertIn("198.235.24.0/24", feed.cidrs)
        self.assertIn("fallback", feed.message.lower())

    @patch("threat_intel.scanner_inventory_maintenance._fetch_json")
    def test_fetch_binaryedge_feed_parses_minions(self, mock_fetch):
        mock_fetch.return_value = {"scanners": ["3.24.125.137", "3.64.114.120"]}
        from threat_intel.scanner_inventory_maintenance import fetch_binaryedge_feed

        feed = fetch_binaryedge_feed()
        self.assertEqual(feed.status, "ok")
        self.assertEqual(feed.cidrs, ["3.24.125.137/32", "3.64.114.120/32"])

    @patch("threat_intel.scanner_inventory_maintenance._fetch_text")
    def test_fetch_censys_feed_parses_documented_ranges(self, mock_fetch):
        mock_fetch.return_value = """
        66.132.159.0/24
        162.142.125.0/24
        2602:80d:1000:b0cc:e::/80
        AS398722
        """
        feed = fetch_censys_feed()
        self.assertEqual(feed.status, "ok")
        self.assertIn("162.142.125.0/24", feed.cidrs)
        self.assertIn("66.132.159.0/24", feed.cidrs)
        self.assertIn("2602:80d:1000:b0cc:e::/80", feed.cidrs)


if __name__ == "__main__":
    unittest.main()
