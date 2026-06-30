# Scanner Enrichment Lite — Architecture

System design for the `scanner-enrichment-lite` branch. For quick start and API usage see [SCANNER-LITE.md](./SCANNER-LITE.md). For the full hybrid platform see [ARCHITECTURE.md](./ARCHITECTURE.md) and branch `threat-enrich-agent`.

## Problem statement

Honeypot nodes emit high-volume source IPs. Analysts need to know:

1. **Is this a known scanner?** (benign probe traffic vs real threat)
2. **What external APIs were called and why?** (cost control at ~1000 events/day)
3. **What behavior did the honeypot observe?** (PeopleSoft probes, HEAD fingerprinting, etc.)
4. **How often has this IP hit us today?** (frequency-driven priority)

Scanner-lite answers these with a **deterministic 4-category classifier**, **CSV-first Tier-0**, a **3-step paid cascade**, and **dual-write** to both scanner ops indices and analyst session records (`stingar-enriched-*`).

## System context

```mermaid
flowchart TB
    subgraph external [External]
        HP["STINGAR honeypots"]
        ANALYST["Analyst / demo curl"]
    end

    subgraph lite [Scanner Enrichment Lite :8091]
        SRV["scanner_lite/server.py"]
        ING["stingar_ingest.py"]
        ENR["enrich.py"]
    end

    subgraph config [Config — not runtime HTTP]
        CSV["known_scanner_inventory.csv"]
        FEEDS["config/scanners/feeds/*.json"]
        RANK["eval/ranking.json"]
    end

    subgraph apis [External enrichment APIs]
        AIP["abuseipdb"]
        OTX["otx"]
        GN["greynoise"]
        ASNAPI["ripestat / ip-api / ipinfo"]
    end

    subgraph es [Elasticsearch :9200]
        SLIP["scanner-ip-enrichment-*"]
        SLASN["scanner-asn-batches-*"]
        CACHE["scanner-ip-cache"]
        SESS["stingar-enriched-*"]
    end

    subgraph views [Observability]
        KIB["Kibana :5601"]
    end

    HP --> ING
    ANALYST --> SRV
    SRV --> ENR
    ING --> ENR
    CSV --> ENR
    FEEDS --> ENR
    RANK --> ENR
    ENR --> AIP
    ENR --> OTX
    ENR --> GN
    ENR --> ASNAPI
    ENR --> SLIP
    ENR --> SLASN
    ENR --> CACHE
    ENR --> SESS
    SLIP --> KIB
    SLASN --> KIB
    SESS --> KIB
```

## Deployment topology

```mermaid
flowchart LR
    subgraph docker [docker compose]
        ES["Elasticsearch\n:9200"]
        KB["Kibana\n:5601"]
    end

    subgraph host [Host process]
        API["scanner_lite.server\n:8091"]
    end

    HP["Honeypot webhook"] --> API
    API --> ES
    KB --> ES
    DEPLOY["deploy-scanner-lite.sh"] --> docker
    DEPLOY --> API
```

Single-node local demo. No central server, no sync queue, no LLM at runtime.

## Enrichment pipeline (per event)

```mermaid
flowchart TB
    START["Event in enrich_events()"] --> NORM["_normalize_event()"]
    NORM --> HIST["count_ip_events_today()\n+ batch occurrence"]
    HIST --> ENRIP["enrich_ip()"]

    ENRIP --> CASCADE["run_cascade()"]
    CASCADE --> CSV["① local_csv — always"]
    CSV --> STOP{benign/malicious\nconfidence ≥ 0.8?}
    STOP -->|yes| CLS
    STOP -->|no| PAID["② abuseipdb → otx → greynoise\nmax 3 calls"]
    PAID --> STOP2{stop early?}
    STOP2 --> CLS["classify_outcome()"]

    ENRIP --> HP["honeypot_signals_from_event()"]
    HP -->|behavior tags| CLS

    CLS --> META["build_investigation_metadata()\nevents_today drives frequency"]
    ENRIP --> ASN["resolve_asn()\nripestat → ip-api → ipinfo\nseparate from cascade trace"]

    META --> DOC["scanner-lite document"]
    ASN --> DOC
    DOC --> IDX1["index scanner-ip-enrichment-*"]
    DOC --> SESS["to_stingar_session()"]
    SESS --> IDX2["index stingar-enriched-*"]
```

## Eight endpoints — three roles

Not all eight adapters run on every IP. They have distinct jobs:

```mermaid
flowchart TB
    IP["source_ip"]

    IP --> T0["Classification Tier 0"]
    subgraph T0 ["Always"]
        LC["local_csv"]
    end

    IP --> CAS["Classification cascade — max 3"]
    subgraph CAS ["Ranked from eval/ranking.json"]
        direction LR
        C1["abuseipdb"] --> C2["otx"] --> C3["greynoise"]
    end

    IP --> ASNP["ASN enrichment — every IP"]
    subgraph ASNP ["First success wins"]
        direction LR
        R["ripestat"] --> I["ip_api"] --> P["ipinfo"]
    end

    subgraph EVAL ["Overlap eval only — not runtime cascade"]
        S["shodan_internetdb"]
    end

    T0 --> TRACE["api_call_trace[]"]
    CAS --> TRACE
    ASNP --> ASNFIELD["document.asn\nnot in api_call_trace"]

    LC --> CLS["classify_outcome()"]
    CAS --> CLS
```

| # | Endpoint | Runtime role |
|---|---|---|
| 1 | `local_csv` | Always first; CIDR match against CSV + feed snapshots |
| 2 | `abuseipdb` | Cascade slot 1 |
| 3 | `otx` | Cascade slot 2 |
| 4 | `greynoise` | Cascade slot 3 (intentionally last) |
| 5 | `ripestat` | ASN path |
| 6 | `ip_api` | ASN fallback |
| 7 | `ipinfo` | ASN fallback |
| 8 | `shodan_internetdb` | Eval overlap only today |

## Classifier and metadata

```mermaid
flowchart LR
    SIG["Merged signals\nCSV · APIs · honeypot"] --> CLS["classifier.py\n4 categories"]

    CLS --> B["benign\nknown scanner"]
    CLS --> M["malicious\nabuse / GN / OTX"]
    CLS --> S["suspicious\nhoneypot boost"]
    CLS --> U["unknown\nno strong signal"]

    CLS --> META["metadata.py"]
    EVT["events_today"] --> META
    HPCTX["hpData context"] --> META

    META --> IC["investigation_classification"]
    META --> PR["priority"]
    META --> FT["frequency_tier"]
    META --> BT["behavior_tags"]
```

**Priority rules (simplified):**

| Condition | Priority |
|---|---|
| `malicious` | `critical` |
| `benign` + normal frequency | `low` |
| `benign` + high/excessive frequency | `medium` |
| `peoplesoft_probe` or excessive frequency | `high` |
| `suspicious` or high frequency | `medium` |

## Session record integration

Scanner-lite documents are mapped to the shared STINGAR session schema so Attack Analysis and `/scanner-lite/sessions` work against `stingar-enriched-*`.

```mermaid
flowchart LR
    subgraph liteDoc ["scanner-lite document"]
        OC["outcome_category"]
        IM["investigation_metadata"]
        ST["scanner_tag"]
        TR["api_call_trace"]
    end

    subgraph sessionDoc ["stingar-enriched session"]
        INV["investigation.*"]
        THR["threat.severity"]
        TAX["taxonomy.tags"]
        HP["hp_data.enrichment.scanner_lite"]
        EFF["effective_severity / effective_signals"]
    end

    OC --> INV
    OC --> THR
    IM --> INV
    ST --> TAX
    IM --> HP
    TR --> HP
    INV --> EFF
    TAX --> EFF
```

Mapper: `scanner_lite/session_document.py` → `ElasticsearchDocumentStore.index_documents()`.

## Elasticsearch indices

```mermaid
erDiagram
    SCANNER_IP_ENRICHMENT ||--o{ STINGAR_ENRICHED : "dual-write per event"
    SCANNER_IP_ENRICHMENT }o--|| SCANNER_IP_CACHE : "latest per IP"
    SCANNER_IP_ENRICHMENT }o--o{ SCANNER_ASN_BATCHES : "daily rollup"

    SCANNER_IP_ENRICHMENT {
        ip source_ip
        keyword outcome_category
        object investigation_metadata
        object scanner_tag
        nested api_call_trace
        integer events_today
    }

    STINGAR_ENRICHED {
        ip src_ip
        keyword effective_severity
        keyword effective_signals
        object investigation
        object hp_data
    }

    SCANNER_ASN_BATCHES {
        keyword asn_number
        date batch_date
        flattened category_counts
    }
```

| Index pattern | Writer | Purpose |
|---|---|---|
| `scanner-ip-enrichment-YYYY-MM-DD` | `ScannerLiteStore` | Ops, trace, frequency history source |
| `scanner-ip-cache` | `ScannerLiteStore` | Latest enrichment per IP (bare `enrich/ip`) |
| `scanner-asn-batches-YYYY-MM-DD` | `ScannerLiteStore` | Daily ASN rollups |
| `stingar-enriched-YYYY-MM-DD` | `ElasticsearchDocumentStore` | Analyst session records |

## Module map

```mermaid
flowchart TB
    subgraph entry [Entry points]
        SERVER["scanner_lite/server.py"]
        DEPLOY["scripts/deploy-scanner-lite.sh"]
    end

    subgraph core [Core pipeline]
        ENRICH["enrich.py"]
        CASCADE["cascade.py"]
        CLASS["classifier.py"]
        META["metadata.py"]
        ASN["asn.py"]
        SESSDOC["session_document.py"]
        INGEST["stingar_ingest.py"]
    end

    subgraph endpoints [scanner_lite/endpoints/"]
        REG["registry.py"]
        LC["local_csv.py"]
        ADAPTERS["abuseipdb · otx · greynoise · ..."]
    end

    subgraph eval [Evaluation]
        OVERLAP["eval/overlap.py"]
        GOLDEN["eval/golden_ips.json"]
        RANKING["eval/ranking.json"]
    end

    subgraph shared [Shared threat_intel/]
        SCANNERS["scanners.py"]
        WEBHOOK["webhook_events.py"]
        ESCLIENT["elasticsearch/client.py"]
        DOCSTORE["elasticsearch/document_store.py"]
        SESSQ["elasticsearch/session_query.py"]
    end

    subgraph storage [Storage]
        STORE["storage/es_store.py"]
    end

    SERVER --> ENRICH
    SERVER --> INGEST
    INGEST --> ENRICH
    ENRICH --> CASCADE
    ENRICH --> CLASS
    ENRICH --> META
    ENRICH --> ASN
    ENRICH --> SESSDOC
    ENRICH --> STORE
    SESSDOC --> DOCSTORE
    CASCADE --> REG
    REG --> LC
    REG --> ADAPTERS
    OVERLAP --> RANKING
    SCANNERS --> LC
    WEBHOOK --> INGEST
```

## Frequency / IP history

```mermaid
sequenceDiagram
    participant WH as Webhook call N
    participant EN as enrich_events()
    participant ES as scanner-ip-enrichment-*
    participant MD as metadata.py

    WH->>EN: 1 event for 52.29.178.95
    EN->>ES: count_ip_events_today() → 47
    EN->>MD: events_today=48, events_in_batch=1
    MD-->>EN: frequency_tier=excessive, priority=high
    EN->>ES: index document #48
```

Separate webhook calls accumulate. A single batch of 48 events in one payload produces the same `events_today` without 48 HTTP round-trips.

## Relationship to full stack

```mermaid
flowchart TB
    subgraph liteBranch ["scanner-enrichment-lite (this branch)"]
        LITE["scanner_lite/*\n8091"]
    end

    subgraph fullBranch ["threat-enrich-agent (reference)"]
        WHFULL["stingar/webhook_listener\n8090"]
        HYBRID["HybridEnrichmentClient"]
        CENTRAL["central/server.py"]
        AGENT["main.py Claude agent"]
    end

    subgraph shared [Shared on both branches]
        SCANNERS["threat_intel/scanners.py"]
        ES["Elasticsearch client + templates"]
    end

    HP["Honeypots"] --> LITE
    HP -.-> WHFULL
    WHFULL --> HYBRID --> CENTRAL
    CENTRAL --> AGENT
    LITE --> SCANNERS
    HYBRID --> SCANNERS
    LITE --> ES
    HYBRID --> ES
```

| Capability | Scanner-lite | Full stack |
|---|---|---|
| Scanner CSV + feeds | Yes | Yes |
| 4-category classifier | Yes | Partial (severity + investigation) |
| API cascade + trace | Yes | Different pipeline |
| Central sync | No | Yes |
| Sharing policy / safelist | No | Yes |
| LLM agent | No | Yes |
| Session records (`stingar-*`) | Yes (dual-write) | Yes |

## Design constraints

1. **Cost-aware:** CSV-first; cascade stops at benign/malicious ≥ 0.8 confidence; max 3 paid calls.
2. **Deterministic:** No LLM at runtime; same signals → same outcome.
3. **Strict ES mappings:** Templates must be applied before index creation (`deploy-scanner-lite.sh`).
4. **Elasticsearch only** for lite storage (not SQLite).

## Related documents

| Document | Content |
|---|---|
| [SCANNER-LITE.md](./SCANNER-LITE.md) | Quick start, API table, demo IPs |
| [API-CASCADE.md](./API-CASCADE.md) | Endpoint eval, ranking, cost model |
| [CODE_REVIEW.md](./CODE_REVIEW.md) | Reviewer checklist and verification |
| [DATA-MODEL.md](./DATA-MODEL.md) | Full-stack schema (shared `stingar-*` conventions) |
| [DECISIONS.md](./DECISIONS.md) | ADRs including CSV + feed snapshots |
