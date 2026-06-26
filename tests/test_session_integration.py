"""Tests for stingar session document mapping and IP history frequency."""

from __future__ import annotations

import unittest
from unittest import mock

from scanner_lite.metadata import build_investigation_metadata
from scanner_lite.session_document import to_stingar_session


ENRICHED_DOC = {
    "@timestamp": "2026-06-25T12:00:00+00:00",
    "source_ip": "52.29.178.95",
    "outcome_category": "suspicious",
    "outcome_confidence": 0.82,
    "outcome_reasons": ["Targeted PeopleSoft fingerprinting from unbranded Go HTTP client."],
    "investigation_metadata": {
        "investigation_classification": "active_application_recon",
        "scanner_attribution": "unidentified_go_scanner",
        "behavior_tags": ["peoplesoft_probe", "go_http_client"],
        "frequency_tier": "excessive",
        "priority": "high",
        "events_in_batch": 1,
        "events_today": 48,
    },
    "scanner_tag": None,
    "attack_type": "peoplesoft-scan",
    "honeypot_type": "peoplesoft",
    "api_call_trace": [{"endpoint": "local_csv"}, {"endpoint": "abuseipdb"}],
}

PEOPLESOFT_EVENT = {
    "app": "peoplesoft",
    "srcIp": "52.29.178.95",
    "hpData": {
        "method": "HEAD",
        "path": "/ps/signon.html",
        "eventType": "peoplesoft-scan",
        "headers": {"UserAgent": "Go-http-client/1.1"},
    },
}


class TestSessionDocument(unittest.TestCase):
    def test_maps_outcome_to_investigation_and_severity(self):
        session = to_stingar_session(ENRICHED_DOC, PEOPLESOFT_EVENT, client_id="demo")
        self.assertEqual(session["investigation"]["category"], "suspicious")
        self.assertEqual(session["investigation"]["classification"], "active_application_recon")
        self.assertEqual(session["investigation"]["priority"], "high")
        self.assertEqual(session["threat"]["severity"], "MEDIUM")
        self.assertEqual(session["src_ip"], "52.29.178.95")
        self.assertEqual(session["elastic_metadata"]["pipeline"], "scanner-enrichment-lite")

    def test_scanner_lite_block_on_hp_data(self):
        session = to_stingar_session(ENRICHED_DOC, PEOPLESOFT_EVENT)
        sl = session["hp_data"]["enrichment"]["scanner_lite"]
        self.assertEqual(sl["events_today"], 48)
        self.assertEqual(sl["events_in_batch"], 1)
        self.assertEqual(sl["frequency_tier"], "excessive")
        self.assertIn("behavior:peoplesoft_probe", session["taxonomy"]["tags"])

    def test_known_scanner_taxonomy_tag(self):
        doc = {
            **ENRICHED_DOC,
            "outcome_category": "benign",
            "investigation_metadata": {
                "investigation_classification": "known_scanner",
                "scanner_attribution": "known:Censys",
                "behavior_tags": [],
                "frequency_tier": "normal",
                "priority": "low",
                "events_in_batch": 1,
                "events_today": 1,
            },
            "scanner_tag": {
                "vendor": "Censys",
                "scanner_id": "censys",
                "matched_cidr": "1.2.3.0/24",
            },
        }
        session = to_stingar_session(doc, None)
        self.assertEqual(session["threat"]["severity"], "LOW")
        self.assertIn("scanner:censys", session["taxonomy"]["tags"])


class TestIpHistoryFrequency(unittest.TestCase):
    def test_events_today_drives_frequency_not_batch_only(self):
        meta = build_investigation_metadata(
            outcome={"outcome_category": "suspicious", "confidence": 0.8, "reasons": []},
            scanner_tag=None,
            event=PEOPLESOFT_EVENT,
            events_in_batch=1,
            events_today=48,
        )
        self.assertEqual(meta["events_in_batch"], 1)
        self.assertEqual(meta["events_today"], 48)
        self.assertEqual(meta["frequency_tier"], "excessive")
        self.assertEqual(meta["priority"], "high")

    def test_enrich_events_uses_es_history(self):
        with mock.patch("scanner_lite.enrich.run_cascade") as cascade:
            cascade.return_value = {
                "signals": {},
                "api_call_trace": [],
                "outcome": {"outcome_category": "unknown", "confidence": 0.4, "reasons": []},
            }
            with mock.patch("scanner_lite.enrich.resolve_asn") as asn:
                asn.return_value = {"number": "AS0", "org": "test"}
                with mock.patch("scanner_lite.enrich.ScannerLiteStore") as store_cls:
                    store = mock.MagicMock()
                    store_cls.return_value = store
                    store.count_ip_events_today.return_value = 47
                    store.index_ip_document.return_value = {"indexed": 1, "errors": []}
                    store.index_asn_batches.return_value = {"indexed": 0, "errors": []}

                    from scanner_lite.enrich import enrich_events

                    with mock.patch("scanner_lite.enrich._index_session_documents") as sessions:
                        sessions.return_value = {"indexed": 1, "failed": 0}
                        enrich_events(
                            [{"source_ip": "52.29.178.95", "honeypot_type": "web"}],
                            index_sessions=False,
                        )

                    store.count_ip_events_today.assert_called_once_with("52.29.178.95")
                    indexed_doc = store.index_ip_document.call_args[0][0]
                    self.assertEqual(indexed_doc["investigation_metadata"]["events_today"], 48)


if __name__ == "__main__":
    unittest.main()
