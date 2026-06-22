# Scanner Enrichment Lite

Simplified scanner-first enrichment on the `scanner-enrichment-lite` branch.

Full hybrid architecture: see [REFERENCE.md](../REFERENCE.md) and branch `threat-enrich-agent`.

## What this does

- Tags known scanners from [known_scanner_inventory.csv](../config/scanners/known_scanner_inventory.csv)
- Classifies each IP into **benign**, **malicious**, **suspicious**, or **unknown**
- Runs a **cost-aware API cascade** (1st / 2nd / 3rd best after eval)
- Stores per-IP enrichment in **Elasticsearch** with `api_call_trace`
- Rolls up daily **ASN batches** for ~1000 events/day analysis

No central sync, no sharing policy, no LLM at runtime.

## Architecture

```mermaid
flowchart TB
    subgraph ingest [Ingest]
        API["POST /scanner-lite/enrich/events"]
    end

    subgraph tier0 [Tier0 Free]
        CSV["local_csv CIDR match"]
        ASN["ASN resolve cached per ASN"]
    end

    subgraph cascade [Paid cascade if needed]
        E1["1st ranked API"]
        E2["2nd ranked API"]
        E3["3rd ranked API"]
    end

    subgraph classify [Classifier]
        CAT["benign / malicious / suspicious / unknown"]
    end

    subgraph store [Elasticsearch]
        IPIdx["scanner-ip-enrichment-YYYY-MM-DD"]
        ASNIdx["scanner-asn-batches-YYYY-MM-DD"]
    end

    API --> CSV
    CSV -->|known scanner| CAT
    CSV -->|no match| ASN --> E1 --> E2 --> E3
    E1 --> CAT
    E2 --> CAT
    E3 --> CAT
    CAT --> IPIdx
    CAT --> ASNIdx
```

## Per-IP API call diagram

```mermaid
flowchart LR
    IP["source_ip"]

    IP --> CSV["local_csv $0"]
    CSV -->|198.235.24.10 match| BENIGN["benign STOP"]
    CSV -->|203.0.113.42 no match| GN["greynoise $0"]
    GN -->|malicious| MAL["malicious STOP"]
    GN -->|unknown| AIP["abuseipdb"]
    AIP --> OTX["otx if still unresolved"]
```

Each enriched document stores `api_call_trace[]` showing exactly which endpoints fired.

## Quick start

```bash
export STINGAR_STORAGE_BACKEND=elasticsearch
export ELASTICSEARCH_URL=http://127.0.0.1:9200

./scripts/deploy-scanner-lite.sh up
```

Or manually:

```bash
docker compose -f deploy/docker-compose.yml up -d elasticsearch
.venv-1/bin/python -m scanner_lite.server
```

## API endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | ES reachability |
| POST | `/scanner-lite/enrich/ip` | Single IP enrichment |
| POST | `/scanner-lite/enrich/events` | Batch honeypot events |
| GET | `/scanner-lite/batches/asn?date=YYYY-MM-DD` | ASN batch rollups |
| GET | `/scanner-lite/eval/ranking` | Current cascade ranking |
| POST | `/scanner-lite/eval/run` | Re-run overlap eval |

## Demo expectations

| IP | Expected | Paid API calls |
|---|---|---|
| `198.235.24.10` | benign + scanner tag | 0 |
| `203.0.113.42` | malicious or suspicious | 1+ |

## Storage

Elasticsearch only (not SQLite). Indices:

- `scanner-ip-enrichment-*` — per-event enrichment + `api_call_trace`
- `scanner-ip-cache` — latest enrichment per source IP
- `scanner-asn-batches-*` — daily ASN rollups

See [API-CASCADE.md](API-CASCADE.md) for endpoint evaluation details.
