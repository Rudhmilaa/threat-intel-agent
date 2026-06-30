# Reference: Full Threat Intel Agent

This branch (`scanner-enrichment-lite`) is a **simplified scanner-first enrichment** path.

The full hybrid local/central architecture, policy sync, incident clustering, and Claude agent live on the **`threat-enrich-agent`** branch. Use that branch as background knowledge and reference implementation.

| Branch | Purpose |
|---|---|
| `threat-enrich-agent` | Full STINGAR hybrid enrichment platform |
| `scanner-enrichment-lite` | Scanner tagging, 4-category outcomes, ASN batches, cost-aware API cascade |

Reused from the reference codebase on this branch:

- [`threat_intel/scanners.py`](threat_intel/scanners.py) — CIDR scanner inventory
- [`config/scanners/known_scanner_inventory.csv`](config/scanners/known_scanner_inventory.csv)
- [`threat_intel/elasticsearch/`](threat_intel/elasticsearch/) — ES HTTP client
- [`deploy/docker-compose.yml`](deploy/docker-compose.yml) — local Elasticsearch

Not required for lite demos: `central/`, `stingar/`, `main.py` agent runtime.

Documentation: [docs/SCANNER-LITE-ARCHITECTURE.md](docs/SCANNER-LITE-ARCHITECTURE.md) · [docs/CODE_REVIEW.md](docs/CODE_REVIEW.md)
