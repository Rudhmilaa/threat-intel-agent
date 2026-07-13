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

    def test_inventory_version_on_session_when_present(self):
        doc = {
            **ENRICHED_DOC,
            "investigation_metadata": {
                **ENRICHED_DOC["investigation_metadata"],
                "scanner_inventory_version": 42,
                "scanner_inventory_refreshed_at": "2026-06-22T10:00:00+00:00",
            },
        }
        session = to_stingar_session(doc, PEOPLESOFT_EVENT)
        sl = session["hp_data"]["enrichment"]["scanner_lite"]
        self.assertEqual(sl["inventory_version"], 42)
        self.assertEqual(sl["inventory_refreshed_at"], "2026-06-22T10:00:00+00:00")

    def test_outcome_category_and_summary_on_session(self):
        doc = {
            **ENRICHED_DOC,
            "outcome_category": "suspicious",
            "scanner_tag": {
                "vendor": "Censys",
                "scanner_id": "censys",
                "matched_cidr": "162.142.125.0/24",
            },
            "investigation_metadata": {
                **ENRICHED_DOC["investigation_metadata"],
                "scanner_inventory_version": 7,
            },
        }
        session = to_stingar_session(doc, PEOPLESOFT_EVENT)
        self.assertEqual(session["outcome_category"], "suspicious")
        self.assertEqual(session["investigation"]["category"], "suspicious")
        summary = session["outcome_summary"]
        self.assertEqual(summary["priority"], "high")
        self.assertIn("peoplesoft_probe", summary["behavior_tags"])
        self.assertEqual(summary["inventory_version"], 7)

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

    def test_preserves_c2_engine_enrichment_from_event(self):
        event = {
            **PEOPLESOFT_EVENT,
            "c2_host": ["1.2.3.4"],
            "hpData": {
                **PEOPLESOFT_EVENT["hpData"],
                "playbook_hash": "pb:9f2c41deadbeef",
                "payload_refs": [
                    {
                        "sha256": "af3c9b1e2ed02578ca1066c8235ba4f991e645f89012406c639dbccc6582eec8",
                        "status": "ok",
                    }
                ],
                "enrichment": {
                    "version": "mvp-1",
                    "c2s": [{"ip": "1.2.3.4", "stage": "served_bytes", "url": "http://1.2.3.4/x.sh"}],
                    "payloads": [
                        {
                            "sha256": "af3c9b1e2ed02578ca1066c8235ba4f991e645f89012406c639dbccc6582eec8",
                            "family": "mirai",
                        }
                    ],
                    "playbook_hash": "pb:9f2c41deadbeef",
                    "signals": ["c2_attack", "novel_payload"],
                },
            },
        }
        session = to_stingar_session(ENRICHED_DOC, event)
        enc = session["hp_data"]["enrichment"]
        self.assertEqual(enc["version"], "mvp-1")
        self.assertEqual(enc["signals"], ["c2_attack", "novel_payload"])
        self.assertEqual(enc["c2s"][0]["ip"], "1.2.3.4")
        self.assertEqual(enc["payloads"][0]["family"], "mirai")
        self.assertEqual(enc["playbook_hash"], "pb:9f2c41deadbeef")
        self.assertIn("scanner_lite", enc)
        self.assertEqual(session["hp_data"]["playbook_hash"], "pb:9f2c41deadbeef")

    def test_lifts_c2_engine_fields_without_annotator_stamp(self):
        event = {
            **PEOPLESOFT_EVENT,
            "c2_host": ["185.196.8.22"],
            "hpData": {
                **PEOPLESOFT_EVENT["hpData"],
                "iocs_c2_hosts": ["185.196.8.22"],
                "playbook_hash": "9f2c41deadbeef9f2c41deadbeef9f2c41de",
                "playbook_canonical": "wget <URL> -o <TMP>\nchmod +x <TMP>",
                "payload_refs": [
                    {
                        "kind": "download",
                        "sha256": "af3c9b1e2ed02578ca1066c8235ba4f991e645f89012406c639dbccc6582eec8",
                        "status": "ok",
                        "attempted_url": "http://185.196.8.22/armv7l",
                    }
                ],
            },
        }
        session = to_stingar_session(ENRICHED_DOC, event)
        enc = session["hp_data"]["enrichment"]
        self.assertEqual(enc["c2s"][0]["ip"], "185.196.8.22")
        self.assertEqual(enc["payloads"][0]["sha256"], "af3c9b1e2ed02578ca1066c8235ba4f991e645f89012406c639dbccc6582eec8")
        self.assertEqual(enc["payloads"][0]["kind"], "download")
        self.assertEqual(enc["payloads"][0]["status"], "ok")
        self.assertEqual(enc["payloads"][0]["attempted_url"], "http://185.196.8.22/armv7l")
        self.assertEqual(enc["playbook_hash"], "9f2c41deadbeef9f2c41deadbeef9f2c41de")
        self.assertEqual(enc["playbook"]["exact_key"], "9f2c41deadbeef9f2c41deadbeef9f2c41de")
        self.assertEqual(enc["playbook"]["canonical"], "wget <URL> -o <TMP>\nchmod +x <TMP>")
        self.assertEqual(session["hp_data"]["playbook_canonical"], "wget <URL> -o <TMP>\nchmod +x <TMP>")


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
