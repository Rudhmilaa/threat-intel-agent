# Enrichment Pipeline

How deterministic threat intelligence enrichment works in this repo.

## Overview

Enrichment transforms a honeypot event (or source IP) into:

1. An **intelligence summary** — severity, investigation outcome, campaign, threat actor
2. An **Elasticsearch document** — denormalized event + enrichment fields
3. **Incident clusters** — grouped events with MITRE ATT&CK context and priority scores

Two execution paths exist:

| Path | Entry | Use case |
|---|---|---|
| **Deterministic pipeline** | `enrichment_core.enrich_events_batch()` | Production STINGAR/webhook flow |
| **Claude agent** | `main.run_threat_intel_agent()` | Interactive IOC investigation via central LLM gateway |

After the H1 refactor, the deterministic path does **not** import `main.py`.

## Pipeline stages

```
events[]
    │
    ▼
local_pipeline.enrich_events_locally()     ← STINGAR node entry
    or
pipeline.enrich_events_for_client()        ← central direct entry
    │
    ▼
enrichment_core.enrich_events_batch()
    │
    ├─ configure_client(client_id)         ← load scanner table for client
    ├─ filter_new_ips()                    ← intelligence cache dedup
    │
    for each event:
    ├─ cache hit? → reuse summary
    ├─ cache miss? → build_intelligence_summary(ip)
    │       ├─ calculate_enriched_severity_tool()
    │       ├─ classify_investigation_outcome_tool()
    │       ├─ build_campaign_profile()
    │       └─ attribute_threat_actor()
    ├─ apply_policy_to_summary()           ← safelist caps
    ├─ convert_to_elastic_document()
    ├─ annotate_document_policy()
    └─ build_document_taxonomy()
    │
    ├─ build_incident_clusters()
    ├─ prioritize_incidents()
    └─ document_store.index_documents()    ← ES write (sanitized)
```

## Severity vs investigation

These are **separate outputs** by design.

### Severity (`threat_intel/severity.py`)

Answers: **How dangerous is this IP?**

Inputs:
- IP reputation (abuse score, threat types, malware associations)
- Scanner classification
- Anonymizer (Tor/VPN/proxy) context
- GreyNoise-style noise classification
- IOC timeline (observation count, trend)

Output:
```json
{
  "threat_score": 72,
  "confidence_score": 65,
  "severity": "HIGH",
  "risk_factors": ["High abuse confidence score", "Known malware associations"]
}
```

A Cortex Xpanse scanner IP may still score **HIGH** on abuse metrics.

### Investigation (`threat_intel/investigation.py`)

Answers: **What kind of activity is this, and how should analysts respond?**

Inputs: same enrichment sources, but applies classification rules:

| Classification | Typical trigger |
|---|---|
| `known_scanner` | Matched in scanner inventory |
| `known_scanner_excessive_probe` | Scanner + high timeline count |
| `likely_malicious_infrastructure` | High severity + malware families |
| `anonymizer_context` | Tor/VPN/proxy (context, not auto-malicious) |
| `informational` | Low-signal activity |

Output:
```json
{
  "investigation_classification": "known_scanner",
  "category": "benign_scanner",
  "priority": "LOW",
  "reasons": ["Matched Cortex Xpanse CIDR range"]
}
```

**Why both?** Severity feeds risk dashboards; investigation drives analyst workflow. A noisy scanner can be HIGH severity but LOW investigation priority.

## Intelligence summary shape

Built by `threat_intel/intelligence_summary.py`:

```json
{
  "indicator": "203.0.113.42",
  "severity": { "...": "..." },
  "investigation": { "...": "..." },
  "campaign": {
    "campaign_name": "...",
    "campaign_type": "botnet_c2",
    "malware_families": ["Emotet"],
    "related_ips": [],
    "related_domains": [],
    "related_hashes": []
  },
  "threat_actor": {
    "threat_actor": "...",
    "attribution_confidence": "medium",
    "motivation": "financial"
  }
}
```

This summary is cached per `(client_id, source_ip)` in the intelligence cache.

## Module map

| Module | Responsibility |
|---|---|
| `lookups.py` | Mock/live IOC backends: IP, hash, domain, MITRE, timeline, GreyNoise, anonymizer |
| `severity.py` | Multi-source threat scoring |
| `investigation.py` | Outcome classification + tool wrapper |
| `campaign.py` | Campaign profiling from related IOCs |
| `intelligence_summary.py` | Orchestrates summary build + batch helpers |
| `documents.py` | Honeypot event → ES document |
| `incidents.py` | Batch summary, clustering, MITRE mapping, priority queue, recurring attacker |
| `scanners.py` | Scanner registry + `classify_known_scanner()` |
| `scanner_inventory_maintenance.py` | Auto-refresh vendor feed snapshots |
| `taxonomy.py` | Structured tags on documents and clusters |
| `safelist.py` | CIDR safelist + severity capping |
| `policy_engine.py` | Apply safelist, evaluate shareability, sanitize |
| `enrichment_core.py` | Batch orchestration |
| `local_pipeline.py` | Local-first wrapper with `pipeline_label=local_enrichment` |

## Scanner Tier-0

Scanner attribution runs **before** severity/investigation and can downgrade investigation priority.

### Data sources

1. **`config/scanners/known_scanner_inventory.csv`** — analyst-maintained vendor rows
2. **`config/scanners/feeds/*.json`** — large rotating feeds (e.g. BinaryEdge ~4.8k CIDRs)
3. **`config/clients/{client_id}_scanners.json`** — per-deployment overrides
4. **`config/scanners/default_scanners.json`** — fallback when CSV absent

### Loading

`ScannerRegistry.from_inventory()` merges CSV + feed snapshots + client JSON. Longest-prefix CIDR match wins.

### Maintenance

`scanner_inventory_maintenance.py` refreshes feeds from vendor pages/APIs (Censys, Xpanse, ONYPHE, LeakIX, BinaryEdge). Triggered via:

- `POST /api/v1/scanners/refresh` (central)
- GitHub Actions weekly workflow
- Agent tool `refresh_scanner_inventory`

## Incident clustering

`incidents.py` groups enriched documents by `(source_ip, campaign_name)`:

- Aggregates attack types, destination ports, malware families
- Maps clusters to MITRE techniques via attack type + campaign type + malware family
- Detects recurring attackers from historical mock DB
- Attaches taxonomy tags via `taxonomy.attach_taxonomy_to_clusters()`

Priority scoring weights:
- Severity (CRITICAL=100 … INFORMATIONAL=0)
- Event count
- Historical recurrence + trend

## Cache and dedup

New-IP detection uses the **intelligence cache** (`intel-summaries` index or SQLite), not a separate seen-IPs JSON file.

```python
# stingar/client.py
new_ips = get_intelligence_cache().filter_new_ips(client_id, source_ips)
```

On cache miss, `build_intelligence_summary()` runs once per IP; subsequent events for the same IP reuse the cached summary with `cache_status: hit`.

## Agent path vs deterministic path

| Aspect | Deterministic | Claude agent |
|---|---|---|
| Entry | `enrichment_core` | `main.run_threat_intel_agent()` |
| Speed | Fast, no API calls (mock data) | Slower, uses Anthropic API |
| Tool selection | Fixed pipeline | Dynamic tool use (16 tools) |
| Production use | STINGAR webhook + sync | Central LLM gateway only |
| Output | ES documents + clusters | Natural language report |

Agent tools re-export lookup/severity functions from `threat_intel/` modules. The agent is **not** on the hot path for honeypot ingest.

## Extension points

### Add a lookup source

1. Add function to `threat_intel/lookups.py`
2. Wire into `calculate_enriched_severity()` and/or `classify_investigation_outcome()`
3. Optionally expose as agent tool in `main.py`

### Add a taxonomy tag

1. Add classification logic in `threat_intel/taxonomy.py`
2. Tags appear on documents (`taxonomy.tags`) and incident clusters

### Add a scanner vendor

1. Add CSV row or feed snapshot under `config/scanners/`
2. Or add vendor parser in `scanner_inventory_maintenance.py`

## Related docs

- [DATA-MODEL.md](./DATA-MODEL.md) — document schema and indices
- [POLICY-AND-SHARING.md](./POLICY-AND-SHARING.md) — safelist and shareability
- [ARCHITECTURE.md](./ARCHITECTURE.md) — where the pipeline runs
