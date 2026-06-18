"""Tests for central sync shareability defense-in-depth."""

from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

os.environ["STINGAR_STORAGE_BACKEND"] = "sqlite"
os.environ.setdefault("STINGAR_LOCAL_CACHE_PATH", tempfile.mktemp(suffix="_sync_test_cache.db"))


class SyncShareabilityTests(unittest.TestCase):
    def test_sync_rejects_private_destination_documents(self):
        from fastapi import HTTPException

        from central.server import SyncEventsRequest, sync_events

        request = SyncEventsRequest(
            client_id="example-stingar-01",
            enriched_documents=[
                {
                    "source": {"ip": "198.235.24.10"},
                    "destination": {"ip": "10.0.0.25"},
                    "investigation": {"classification": "known_scanner_high_noise"},
                    "threat": {"severity": "LOW"},
                }
            ],
        )

        with mock.patch("central.server.get_document_store", return_value=None):
            with self.assertRaises(HTTPException) as ctx:
                sync_events(request)

        self.assertEqual(ctx.exception.status_code, 403)

    def test_sync_accepts_public_destination_documents(self):
        from central.server import SyncEventsRequest, sync_events

        request = SyncEventsRequest(
            client_id="example-stingar-01",
            enriched_documents=[
                {
                    "source": {"ip": "198.235.24.10"},
                    "destination": {"ip": "203.0.113.50"},
                    "investigation": {"classification": "known_scanner_high_noise"},
                    "threat": {"severity": "LOW"},
                }
            ],
        )

        with mock.patch("central.server.get_document_store", return_value=None):
            result = sync_events(request)

        self.assertEqual(result["documents_accepted"], 1)
        self.assertEqual(result["summaries_merged"], 1)


if __name__ == "__main__":
    unittest.main()
