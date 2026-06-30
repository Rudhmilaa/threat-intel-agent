"""Tests for Fluentd ingest normalization and endpoint."""

from __future__ import annotations

import unittest
from unittest import mock

from scanner_lite.fluentd_normalize import normalize_fluentd_payload


PEOPLESOFT_FLUENTD = {
    "app": "peoplesoft",
    "srcIp": "52.29.178.95",
    "hpData": {
        "method": "HEAD",
        "path": "/ps/signon.html",
        "eventType": "peoplesoft-scan",
        "headers": {"UserAgent": "Go-http-client/1.1"},
    },
}


class TestFluentdNormalize(unittest.TestCase):
    def test_single_record_dict(self):
        payload = normalize_fluentd_payload(PEOPLESOFT_FLUENTD)
        self.assertEqual(len(payload["events"]), 1)
        event = payload["events"][0]
        self.assertEqual(event["srcIp"], "52.29.178.95")
        self.assertEqual(event["hpData"]["eventType"], "peoplesoft-scan")

    def test_fluentd_record_wrapper(self):
        payload = normalize_fluentd_payload({"record": PEOPLESOFT_FLUENTD})
        self.assertEqual(payload["events"][0]["srcIp"], "52.29.178.95")

    def test_batch_events_wrapper(self):
        payload = normalize_fluentd_payload({"events": [PEOPLESOFT_FLUENTD]})
        self.assertEqual(len(payload["events"]), 1)


class TestFluentdIngestEndpoint(unittest.TestCase):
    def test_ingest_fluentd_endpoint(self):
        from fastapi.testclient import TestClient

        from scanner_lite.server import app

        with mock.patch("scanner_lite.server.process_stingar_payload") as process:
            process.return_value = {
                "status": "accepted",
                "service": "scanner-enrichment-lite",
                "received_events": 1,
                "enriched_count": 1,
                "category_counts": {"suspicious": 1},
                "total_api_calls": 2,
                "es_stats": {"indexed": 1},
                "session_es_stats": {"indexed": 1, "failed": 0},
            }
            client = TestClient(app)
            response = client.post("/ingest/fluentd", json=PEOPLESOFT_FLUENTD)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["enriched_count"], 1)
        called_payload = process.call_args[0][0]
        self.assertIn("events", called_payload)
        self.assertEqual(called_payload["events"][0]["srcIp"], "52.29.178.95")


if __name__ == "__main__":
    unittest.main()
