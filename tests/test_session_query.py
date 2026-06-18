"""Tests for the session query language (no Elasticsearch required)."""

from __future__ import annotations

import unittest

from threat_intel.elasticsearch.session_query import parse_session_query, session_query_to_es


class SessionQueryTests(unittest.TestCase):
    def test_parse_severity_range(self):
        terms = parse_session_query("severity:>=high src_ip:203.0.113.42")
        self.assertEqual(len(terms), 2)
        self.assertEqual(terms[0].field, "severity")
        self.assertEqual(terms[0].range_op, ">=")
        self.assertEqual(terms[0].value, "high")

    def test_parse_negation_and_wildcard(self):
        terms = parse_session_query("-signal:internal family:mirai*")
        self.assertTrue(terms[0].negated)
        self.assertTrue(terms[1].value.endswith("*"))

    def test_bare_ip_routes_to_src_ip(self):
        terms = parse_session_query("203.0.113.42")
        self.assertEqual(terms[0].field, "src_ip")

    def test_builds_es_bool_query(self):
        body = session_query_to_es(
            "severity:>=high honeypot:cowrie",
            client_id="example-stingar-01",
            hours=24,
        )
        self.assertIn("query", body)
        self.assertIn("bool", body["query"])
        filters = body["query"]["bool"]["filter"]
        self.assertTrue(any("elastic_metadata.client_id" in str(f) for f in filters))


if __name__ == "__main__":
    unittest.main()
