"""Tests for ASN batch rollups."""

import unittest

from scanner_lite.asn import build_asn_batches


class TestAsnBatches(unittest.TestCase):
    def test_groups_by_asn(self):
        docs = [
            {
                "source_ip": "198.235.24.10",
                "outcome_category": "benign",
                "asn": {"number": "AS396982", "org": "Google"},
                "api_call_trace": [{"endpoint": "local_csv"}],
                "attack_type": "probe",
            },
            {
                "source_ip": "198.235.24.11",
                "outcome_category": "benign",
                "asn": {"number": "AS396982", "org": "Google"},
                "api_call_trace": [{"endpoint": "local_csv"}],
                "attack_type": "probe",
            },
            {
                "source_ip": "203.0.113.42",
                "outcome_category": "malicious",
                "asn": {"number": "AS12345", "org": "Evil ISP"},
                "api_call_trace": [{"endpoint": "local_csv"}, {"endpoint": "greynoise"}],
                "attack_type": "ssh_bruteforce",
            },
        ]
        batches = build_asn_batches(docs, batch_date="2026-06-15")
        self.assertEqual(len(batches), 2)
        by_asn = {b["asn_number"]: b for b in batches}
        self.assertEqual(by_asn["AS396982"]["event_count"], 2)
        self.assertEqual(len(by_asn["AS396982"]["unique_ips"]), 2)
        self.assertEqual(by_asn["AS396982"]["category_counts"]["benign"], 2)
        self.assertEqual(by_asn["AS12345"]["api_calls_total"], 2)


if __name__ == "__main__":
    unittest.main()
