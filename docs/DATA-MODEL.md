# Data Model

Elasticsearch indices, document schemas, and configuration layout for threat-intel-agent.

## Index inventory

| Index | Shape | Writer | Purpose |
|---|---|---|---|
| `stingar-YYYY-MM-DD` | Daily append | `document_store.index_documents()` | Enriched honeypot session/event documents |
| `intel-summaries` | Upsert by `(client_id, ip)` | Intelligence cache backend | IP summary cache + dedup |

### ILM

Daily session indices use the policy in [`es/ilm/stingar-enriched-policy.json`](../es/ilm/stingar-enriched-policy.json) (180-day retention, delete phase).

Index templates:
- [`es/templates/stingar-enriched.json`](../es/templates/stingar-enriched.json) — session/event mappings
- [`es/templates/intel-summaries.json`](../es/templates/intel-summaries.json) — IP cache mappings

Apply templates before first write (see [DEPLOYMENT.md](./DEPLOYMENT.md)).

## Storage backend switch

| Env var | Value | Behavior |
|---|---|---|
| `STINGAR_STORAGE_BACKEND` | `elasticsearch` (default) | Write to ES indices above |
| `STINGAR_STORAGE_BACKEND` | `sqlite` | Use SQLite files under `data/` (tests, air-gapped dev) |

Supporting env vars for Elasticsearch:

| Variable | Default |
|---|---|
| `STINGAR_ES_URL` | `http://127.0.0.1:9200` |
| `STINGAR_ES_USER` | (none) |
| `STINGAR_ES_PASSWORD` | (none) |

## Enriched document schema

Produced by `threat_intel/documents.convert_to_elastic_document()`:

```json
{
  "@timestamp": "2026-06-15T12:00:00+00:00",

  "event": {
    "source": "stingar_honeypot",
    "type": "honeypot_attack",
    "original": { "...raw honeypot event..." }
  },

  "source": {
    "ip": "203.0.113.42",
    "port": 55231
  },

  "destination": {
    "ip": "10.0.0.25",
    "port": 22
  },

  "network": {
    "protocol": "ssh",
    "transport": "tcp"
  },

  "stingar": {
    "sensor_id": "stingar-duke-sensor-01",
    "honeypot_type": "cowrie",
    "attack_type": "ssh_bruteforce"
  },

  "threat": {
    "indicator": { "ip": "203.0.113.42", "type": "ip_address" },
    "severity": "CRITICAL",
    "threat_score": 85,
    "confidence_score": 70,
    "risk_factors": ["..."]
  },

  "investigation": {
    "classification": "likely_malicious_infrastructure",
    "category": "malware_c2",
    "priority": "HIGH",
    "reasons": ["..."]
  },

  "campaign": {
    "name": "Emotet Campaign",
    "type": "botnet_c2",
    "confidence": "medium",
    "malware_families": ["Emotet"],
    "related_ips": [],
    "related_domains": [],
    "related_hashes": []
  },

  "threat_actor": {
    "name": "Unknown",
    "confidence": "low",
    "motivation": "financial"
  },

  "elastic_metadata": {
    "document_type": "stingar_enriched_honeypot_event",
    "pipeline": "local_enrichment",
    "version": "1.0",
    "cache_status": "miss",
    "cache_key": "203.0.113.42",
    "client_id": "example-stingar-01"
  },

  "taxonomy": {
    "tags": ["known_scanner.cortex-xpanse", "intent:service_probe"]
  },

  "policy": {
    "safelist": { "...": "..." }
  }
}
```

### Fields added at index time

| Field | Added by | Purpose |
|---|---|---|
| `elastic_metadata.client_id` | `enrichment_core` | Partition by deployment |
| `elastic_metadata.cache_status` | `enrichment_core` | `hit` or `miss` |
| `elastic_metadata.pipeline` | `enrichment_core` | `local_enrichment` or `threat_intelligence_enrichment` |
| `taxonomy` | `taxonomy.build_document_taxonomy()` | Structured analyst tags |
| `policy` | `policy_engine.annotate_document_policy()` | Safelist match metadata |
| `effective_severity` | ES template / future tier split | Filterable severity after policy |
| `effective_signals` | ES template / future tier split | Denormalized signal list for query |

## Intelligence summary (cache value)

Stored in `intel-summaries` keyed by `(client_id, source_ip)`:

```json
{
  "indicator": "203.0.113.42",
  "severity": {
    "severity": "HIGH",
    "threat_score": 72,
    "confidence_score": 65,
    "risk_factors": ["..."]
  },
  "investigation": {
    "investigation_classification": "known_scanner",
    "category": "benign_scanner",
    "priority": "LOW",
    "reasons": ["..."]
  },
  "campaign": { "...": "..." },
  "threat_actor": { "...": "..." }
}
```

Central `sync_events` merges received documents into this cache without re-enriching.

## Honeypot event input

Minimum fields expected per event:

| Field | Example | Required |
|---|---|---|
| `source_ip` | `203.0.113.42` | Yes |
| `destination_ip` | `10.0.0.25` | No |
| `destination_port` | `22` | No |
| `attack_type` | `ssh_bruteforce` | No |
| `protocol` | `ssh` | No |
| `transport` | `tcp` | No |
| `sensor_id` | `stingar-duke-sensor-01` | No |
| `honeypot_type` | `cowrie` | No |

Validated by `threat_intel/protocols.validate_honeypot_event()`.

## Session query language

Implemented in `threat_intel/elasticsearch/session_query.py`. Exposed via `GET /api/v1/sessions?q=...`.

### Field aliases

| Alias | Indexed field |
|---|---|
| `src_ip` | `src_ip` |
| `severity` | `effective_severity` |
| `signal` | `effective_signals` |
| `verdict` | `investigation.classification` |
| `family` | `campaign.name` |
| `honeypot` | `stingar.honeypot_type` |
| `protocol` | `network.protocol` |
| `sensor` | `stingar.sensor_id` |
| `client_id` | `elastic_metadata.client_id` |
| `country` / `location` | `source.geo.country_code` |

### Query examples

```
severity:>=high
src_ip:203.0.113.42
verdict:known_scanner
signal:known_scanner -severity:informational
hours=24 (query param, not in q string)
```

Bare tokens route automatically: IPs → `src_ip`, SHA256 → `payload`, otherwise → `signal`.

## Config file layout

```
config/
├── scanners/
│   ├── known_scanner_inventory.csv    # Vendor CIDR inventory
│   ├── default_scanners.json          # Fallback when CSV absent
│   └── feeds/
│       └── binaryedge.json            # Large dynamic feed snapshot
├── safelist/
│   └── default_safelist.json          # Global safelist ranges
└── clients/
    ├── api_keys.example.json          # Per-client API key template
    ├── example-stingar-01_scanners.json
    ├── example-stingar-01_safelist.json
    └── example-stingar-01_sharing_policy.json
```

Each STINGAR deployment is identified by **`client_id`**. Per-client JSON files override global defaults.

## Incident cluster shape (API response)

Returned in enrichment batch results (not a separate ES index today):

```json
{
  "incident_id": "incident-12345",
  "source_ip": "203.0.113.42",
  "campaign": "Emotet Campaign",
  "severity": "CRITICAL",
  "event_count": 5,
  "attack_types": ["ssh_bruteforce"],
  "mitre_attack": {
    "techniques": [{"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"}],
    "tactics": ["Credential Access"],
    "detection_suggestions": ["..."]
  },
  "taxonomy": {
    "tags": ["intent:credential_attack"]
  },
  "priority_score": 145
}
```

## Out of scope

This repo does **not** define or write:

- `payloads`, `infra`, `playbooks`, `edges` object indices
- `observations-*` append streams
- `intel-feeds` index (scanner data lives in CSV + JSON snapshots instead)
- `hp_data.enrichment.c2` / payload stamping (future message-cube ingest path)

## Related docs

- [ENRICHMENT.md](./ENRICHMENT.md) — how summaries are built
- [API-REFERENCE.md](./API-REFERENCE.md) — `GET /api/v1/sessions`
- [DEPLOYMENT.md](./DEPLOYMENT.md) — ES bootstrap
