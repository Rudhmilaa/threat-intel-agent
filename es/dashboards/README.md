# Kibana dashboards

Elasticsearch is the **primary store** for enriched STINGAR sessions. Import or build Kibana views against these index patterns:

| Index pattern | Purpose |
|---|---|
| `stingar-*` | Attack Analysis session list — filter/sort on `effective_severity`, `effective_signals`, `src_ip` |
| `intel-summaries` | IP intelligence summary cache (ops/debug) |

## Recommended views

1. **Attack Analysis** — Data table on `stingar-enriched-*`, columns: `@timestamp`, `effective_severity`, `src_ip`, `effective_signals`, `stingar.honeypot_type`, `investigation.classification`
2. **Severity over time** — Lens area chart, split by `effective_severity`
3. **Scanner noise** — filter `investigation.classification: known_scanner_high_noise`

## Session query API

The enrichment server exposes the same filter vocabulary via HTTP:

```bash
curl -H "Authorization: Bearer $CENTRAL_API_KEY" \
  'http://127.0.0.1:8080/api/v1/sessions?q=severity:>=high&hours=24&client_id=example-stingar-01'
```

Query fields match DATA-AND-VIEWS §8d subset: `src_ip`, `signal`, `severity`, `family`, `honeypot`, `verdict`, `client_id`.

## c2-engine dashboards

When merged with c2-engine, reuse `c2-engine/es/dashboards/` for C2 Command Center, entity view, geo map, and payload explorer. Point index patterns at `stingar-enriched-*` until full registry indices land.
