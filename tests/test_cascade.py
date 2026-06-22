"""Tests for API cascade stop conditions."""

import unittest
from unittest.mock import patch

from scanner_lite.cascade import run_cascade, should_stop


class TestCascade(unittest.TestCase):
    def test_should_stop_on_benign(self):
        self.assertTrue(
            should_stop({"outcome_category": "benign", "confidence": 0.95})
        )

    def test_should_not_stop_on_unknown(self):
        self.assertFalse(
            should_stop({"outcome_category": "unknown", "confidence": 0.4})
        )

    @patch("scanner_lite.cascade.load_cascade_order", return_value=["greynoise"])
    def test_known_scanner_stops_after_csv(self, _mock_order):
        result = run_cascade("198.235.24.10")
        self.assertEqual(result["outcome"]["outcome_category"], "benign")
        endpoints = [t["endpoint"] for t in result["api_call_trace"]]
        self.assertEqual(endpoints, ["local_csv"])

    @patch("scanner_lite.cascade.load_cascade_order", return_value=["greynoise", "abuseipdb"])
    def test_malicious_ip_runs_cascade(self, _mock_order):
        result = run_cascade("203.0.113.42")
        self.assertIn(
            result["outcome"]["outcome_category"],
            ("malicious", "suspicious"),
        )
        self.assertGreaterEqual(len(result["api_call_trace"]), 1)


if __name__ == "__main__":
    unittest.main()
