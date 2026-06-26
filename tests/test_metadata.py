"""Tests for investigation metadata derivation."""

import unittest

from scanner_lite.classifier import classify_outcome
from scanner_lite.metadata import (
    build_investigation_metadata,
    derive_behavior_tags,
    extract_honeypot_context,
    frequency_tier,
    honeypot_signals_from_event,
)


PEOPLESOFT_EVENT = {
    "app": "peoplesoft",
    "srcIp": "52.29.178.95",
    "dstIp": "150.136.255.191",
    "dstPort": 8000,
    "hpData": {
        "method": "HEAD",
        "path": "/ps/signon.html",
        "eventType": "peoplesoft-scan",
        "headers": {
            "UserAgent": "Go-http-client/1.1",
            "Host": "150.136.255.191:80",
        },
    },
}


class TestMetadata(unittest.TestCase):
    def test_extract_honeypot_context_from_stingar_event(self):
        ctx = extract_honeypot_context(PEOPLESOFT_EVENT)
        self.assertEqual(ctx["event_type"], "peoplesoft-scan")
        self.assertEqual(ctx["method"], "HEAD")
        self.assertEqual(ctx["user_agent"], "Go-http-client/1.1")
        self.assertEqual(ctx["honeypot_app"], "peoplesoft")

    def test_derive_behavior_tags_peoplesoft_go_scanner(self):
        ctx = extract_honeypot_context(PEOPLESOFT_EVENT)
        tags = derive_behavior_tags(ctx)
        self.assertIn("peoplesoft_probe", tags)
        self.assertIn("head_fingerprint", tags)
        self.assertIn("go_http_client", tags)
        self.assertIn("application_layer_recon", tags)

    def test_frequency_tier_thresholds(self):
        self.assertEqual(frequency_tier(1), "normal")
        self.assertEqual(frequency_tier(10), "high")
        self.assertEqual(frequency_tier(30), "excessive")

    def test_build_metadata_for_aggressive_peoplesoft_scanner(self):
        outcome = {
            "outcome_category": "suspicious",
            "confidence": 0.82,
            "reasons": ["Targeted PeopleSoft fingerprinting from unbranded Go HTTP client."],
        }
        meta = build_investigation_metadata(
            outcome=outcome,
            scanner_tag=None,
            event=PEOPLESOFT_EVENT,
            events_in_batch=1,
            events_today=48,
        )
        self.assertEqual(meta["investigation_classification"], "active_application_recon")
        self.assertEqual(meta["scanner_attribution"], "unidentified_go_scanner")
        self.assertEqual(meta["frequency_tier"], "excessive")
        self.assertEqual(meta["priority"], "high")
        self.assertEqual(meta["events_in_batch"], 1)
        self.assertEqual(meta["events_today"], 48)

    def test_known_scanner_high_noise_metadata(self):
        outcome = {"outcome_category": "benign", "confidence": 0.95, "reasons": []}
        scanner_tag = {"vendor": "Censys"}
        meta = build_investigation_metadata(
            outcome=outcome,
            scanner_tag=scanner_tag,
            event=None,
            events_in_batch=50,
            events_today=50,
        )
        self.assertEqual(meta["investigation_classification"], "known_scanner_high_noise")
        self.assertEqual(meta["scanner_attribution"], "known:Censys")
        self.assertEqual(meta["frequency_tier"], "excessive")
        self.assertEqual(meta["priority"], "medium")

    def test_classifier_boosts_peoplesoft_probe_to_suspicious(self):
        signals = honeypot_signals_from_event(PEOPLESOFT_EVENT)
        outcome = classify_outcome(signals)
        self.assertEqual(outcome["outcome_category"], "suspicious")
        self.assertGreaterEqual(outcome["confidence"], 0.8)


if __name__ == "__main__":
    unittest.main()
