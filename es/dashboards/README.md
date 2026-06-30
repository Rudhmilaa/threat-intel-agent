# Kibana dashboards

Elasticsearch is the **primary store** for enriched sessions. Import or build Kibana views against these index patterns:

| Index pattern | Purpose |
|---|---|
| `stingar-*` | Attack Analysis session list — filter/sort on `effective_severity`, `effective_signals`, `src_ip` |
| `intel-summaries` | IP intelligence summary cache (ops/debug) |
| `scanner-ip-enrichment-*` | Scanner-lite per-IP enrichment — `outcome_category`, `investigation_metadata`, `api_call_trace` |
| `scanner-asn-batches-*` | Scanner-lite daily ASN rollups — `category_counts`, `behavior_tag_counts` |

## Scanner enrichment lite

Pre-built saved objects: [scanner-lite/scanner-lite.ndjson](scanner-lite/scanner-lite.ndjson)

```bash
./scripts/import-scanner-lite-dashboards.sh
# or as part of full deploy:
./scripts/deploy-scanner-lite.sh up
```

Dashboard: **Scanner Enrichment Lite** — IP enrichment table + ASN batch table side by side.

Recommended filters on `scanner-ip-enrichment-*`:

- `outcome_category: suspicious` — honeypot-boosted probes (e.g. PeopleSoft HEAD scans)
- `investigation_metadata.priority: high` — analyst attention queue
- `scanner_tag.vendor: *` — known scanner inventory hits

## Full STINGAR stack (hybrid)

1. **Attack Analysis** — Data table on `stingar-*`, columns: `@timestamp`, `outcome_category`, `src_ip`, `outcome_summary.scanner_vendor`, `stingar.honeypot_type`, `investigation.classification`
2. **Severity over time** — Lens area chart, split by `outcome_category` (preferred) or legacy `effective_severity`
3. **Scanner noise** — filter `investigation.classification: known_scanner_high_noise`

Pre-built Attack Analysis dashboard: [stingar/attack-analysis.ndjson](stingar/attack-analysis.ndjson)

```bash
./scripts/import-stingar-dashboards.sh
# Open: http://127.0.0.1:5601/app/dashboards#/view/stingar-attack-analysis-dashboard
```

See [docs/STINGAR-INTEGRATION.md](../docs/STINGAR-INTEGRATION.md) for STINGAR v2.3 compose + Fluentd wiring.

## Session query API

The enrichment server exposes the same filter vocabulary via HTTP:

```bash
curl -H "Authorization: Bearer $CENTRAL_API_KEY" \
  'http://127.0.0.1:8080/api/v1/sessions?q=severity:>=high&hours=24&client_id=example-stingar-01'
```

Query fields match DATA-AND-VIEWS §8d subset: `src_ip`, `signal`, `severity`, `family`, `honeypot`, `verdict`, `client_id`.

## c2-engine dashboards

When merged with c2-engine, reuse `c2-engine/es/dashboards/` for C2 Command Center, entity view, geo map, and payload explorer. Point index patterns at `stingar-enriched-*` until full registry indices land.
