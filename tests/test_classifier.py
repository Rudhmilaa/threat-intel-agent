"""Tests for 4-category classifier."""

import unittest

from scanner_lite.classifier import classify_outcome


class TestClassifier(unittest.TestCase):
    def test_benign_known_scanner(self):
        outcome = classify_outcome(
            {
                "scanner_tag": {
                    "is_known_scanner": True,
                    "company": "Censys",
                    "confidence": "high",
                    "matched_range": "66.132.159.0/24",
                }
            }
        )
        self.assertEqual(outcome["outcome_category"], "benign")
        self.assertGreaterEqual(outcome["confidence"], 0.9)

    def test_malicious_greynoise(self):
        outcome = classify_outcome(
            {
                "greynoise": {"classification": "malicious"},
                "abuseipdb": {"abuse_confidence_score": 90, "known_malware_associations": ["Emotet"]},
            }
        )
        self.assertEqual(outcome["outcome_category"], "malicious")

    def test_suspicious_abuse_score(self):
        outcome = classify_outcome(
            {
                "abuseipdb": {"abuse_confidence_score": 65, "total_reports": 50},
            }
        )
        self.assertEqual(outcome["outcome_category"], "suspicious")

    def test_unknown_default(self):
        outcome = classify_outcome({})
        self.assertEqual(outcome["outcome_category"], "unknown")


if __name__ == "__main__":
    unittest.main()
