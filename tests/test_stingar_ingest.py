"""Tests for STINGAR webhook ingest into scanner-lite."""

from __future__ import annotations

import unittest
from unittest import mock

from scanner_lite.stingar_ingest import process_stingar_payload
from threat_intel.webhook_events import extract_raw_stingar_events


PEOPLESOFT_EVENT = {
    "app": "peoplesoft",
    "srcIp": "52.29.178.95",
    "dstIp": "150.136.255.191",
    "dstPort": 8000,
    "hpData": {
        "method": "HEAD",
        "path": "/ps/signon.html",
        "eventType": "peoplesoft-scan",
        "headers": {"UserAgent": "Go-http-client/1.1"},
    },
}


class TestStingarIngest(unittest.TestCase):
    def test_extract_raw_events_from_batch_wrapper(self):
        payload = {"events": [PEOPLESOFT_EVENT]}
        events = extract_raw_stingar_events(payload, default_sensor_id="hp-01")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["srcIp"], "52.29.178.95")
        self.assertEqual(events[0]["sensor_id"], "hp-01")

    def test_extract_raw_events_from_list(self):
        events = extract_raw_stingar_events([PEOPLESOFT_EVENT])
        self.assertEqual(len(events), 1)
        self.assertIn("hpData", events[0])

    def test_process_stingar_payload_calls_enrich(self):
        with mock.patch("scanner_lite.stingar_ingest.enrich_events") as enrich:
            enrich.return_value = {
                "enriched_count": 1,
                "category_counts": {"suspicious": 1},
                "total_api_calls": 2,
                "es_stats": {"indexed": 1},
                "enriched_documents": [{"source_ip": "52.29.178.95"}],
            }
            result = process_stingar_payload(
                {"events": [PEOPLESOFT_EVENT]},
                client_id="demo-stingar",
                sensor_id="hp-01",
            )

        enrich.assert_called_once()
        passed_events = enrich.call_args[0][0]
        self.assertEqual(passed_events[0]["srcIp"], "52.29.178.95")
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["received_events"], 1)
        self.assertEqual(result["enriched_count"], 1)
        self.assertEqual(result["category_counts"]["suspicious"], 1)

    def test_process_stingar_payload_empty_raises(self):
        with self.assertRaises(ValueError):
            process_stingar_payload({"events": []})


if __name__ == "__main__":
    unittest.main()
