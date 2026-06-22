# API Cascade and Endpoint Evaluation

How scanner-lite picks and ranks external enrichment APIs to minimize cost at ~1000 events/day.

## Eight endpoints

| # | Endpoint | Module | Cost | Role |
|---|---|---|---|---|
| 1 | local_csv | `endpoints/local_csv.py` | $0 | CIDR match against scanner inventory |
| 2 | ripestat | `endpoints/ripestat.py` | $0 | ASN + org |
| 3 | ip_api | `endpoints/ip_api.py` | $0 | Geo + ASN fallback |
| 4 | greynoise | `endpoints/greynoise.py` | $0 | Scanner vs malicious noise |
| 5 | abuseipdb | `endpoints/abuseipdb.py` | ~$0.001 | Abuse score |
| 6 | shodan_internetdb | `endpoints/shodan_internetdb.py` | $0 | Open ports / tags |
| 7 | otx | `endpoints/otx.py` | $0 | OTX pulse count |
| 8 | ipinfo | `endpoints/ipinfo.py` | $0 | ASN/org enrichment |

`local_csv` always runs first. Paid cascade uses top 3 from eval ranking (default: `greynoise` → `abuseipdb` → `otx`).

## Stop conditions

Cascade stops when:

- Outcome is **benign** or **malicious** with confidence ≥ 0.8
- Max **3** paid API calls per IP

Known scanners from CSV typically stop after `local_csv` with **zero** paid calls.

## Overlap evaluation

Run:

```bash
./scripts/eval-api-overlap.sh
# or
python -m scanner_lite.eval.overlap
```

This:

1. Queries all 8 endpoints against [golden_ips.json](../scanner_lite/eval/golden_ips.json)
2. Maps each response to a 4-category label
3. Builds an **overlap matrix** (pairwise agreement)
4. Ranks endpoints by `success_rate × 0.9 − cost_weight`
5. Writes [ranking.json](../scanner_lite/eval/ranking.json) used by `cascade.py`

## Cost model (1000 events/day)

| Strategy | Est. API calls/day |
|---|---|
| 8 APIs × every IP | up to 8,000 |
| CSV-first + stop on benign | ~0–200 for mostly scanner traffic |
| 3-tier cascade | ~500–1,500 depending on unknown ratio |

ASN metadata is resolved **once per new ASN**, not per IP.

## Environment variables

| Variable | Purpose |
|---|---|
| `ABUSEIPDB_API_KEY` | Live AbuseIPDB (falls back to mock) |
| `GREYNOISE_API_KEY` | Live GreyNoise (falls back to mock) |
| `IPINFO_TOKEN` | ipinfo.io token (optional) |
| `ELASTICSEARCH_URL` | ES base URL (default `http://127.0.0.1:9200`) |

## Ranking output example

```json
{
  "cascade_order": ["greynoise", "abuseipdb", "otx"],
  "ranking": [
    {"rank": 1, "endpoint": "greynoise", "score": 0.85},
    {"rank": 2, "endpoint": "abuseipdb", "score": 0.8},
    {"rank": 3, "endpoint": "otx", "score": 0.65}
  ]
}
```

Refresh ranking after adding golden IPs or changing endpoint adapters.
