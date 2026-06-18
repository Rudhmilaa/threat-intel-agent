# Code Review: Hybrid Local-Global Enrichment

**Project:** `threat-intel-agent` (hybrid enrichment branch)  
**Review date:** 2026-06-15 (updated: ES primary store, scanner inventory feeds, critical/high fixes)  
**Scope:** Hybrid plan implementation + comparison with **c2-engine** (STINGAR v2.3 Local Intel Registry)  
**Reviewer note:** c2-engine is on the same GitLab repo (`origin/c2-engine`, subdirectory `c2-engine/`). See **[C2_ENGINE_INTEGRATION.md](./C2_ENGINE_INTEGRATION.md)** for access instructions and ADR-033-informed porting map. Overlap analysis incorporates DECISIONS.md (ADR-001…033) and DATA-AND-VIEWS.md.

---

## Executive summary

The hybrid plan is **substantially implemented** and now uses **Elasticsearch as the primary store** — aligned with c2-engine and ADR-013/022/027. Enriched sessions land in **`stingar-YYYY-MM-DD`** daily indices (STINGAR naming, ILM-managed); IP summaries upsert to `intel-summaries`; analysts query via `GET /api/v1/sessions?q=…`. Scanner attribution loads from **`known_scanner_inventory.csv`** plus auto-maintained feed snapshots under `config/scanners/feeds/`. SQLite remains an explicit dev/test fallback.

| Area | Verdict |
|---|---|
| **Primary store (Elasticsearch + ILM + query API)** | ✅ Implemented |
| **Scanner inventory + vendor feeds (CSV + maintenance)** | ✅ Implemented |
| Hybrid local-first flow | ✅ Solid |
| Sharing / safelist policy | ✅ Solid |
| Taxonomy + MITRE clusters | ✅ Good analyst value |
| Kibana views | ⚠️ Templates + README; dashboards not bundled yet |
| Federation / sync | ✅ Defense-in-depth on sync; north-star federation deferred |
| Ingest integration | ❌ Not on STINGAR v2.3 fluentd path yet |
| Tiered enrichment | ⚠️ Single batch path; Tier 0/1/2 jobs pending |
| Payload / C2 / playbook intel | ❌ Out of scope — c2-engine owns this |
| Test coverage | ⚠️ 21 tests (hybrid, scanner feeds, session query, sync policy) |

---

## Architecture comparison

### threat-intel-agent (this repo) — updated

```
Honeypot ──▶ webhook_listener / HybridEnrichmentClient
                    │
                    ├─▶ local_pipeline ──▶ enrichment_core
                    ├─▶ policy_engine (safelist + sharing)
                    ├─▶ taxonomy + MITRE clusters
                    │
                    ├─▶ PRIMARY: Elasticsearch
                    │      ├─ stingar-YYYY-MM-DD           (enriched sessions/events, ILM)
                    │      └─ intel-summaries              (IP summary upserts, dedup cache)
                    │
                    ├─▶ Tier-0 scanner lookup
                    │      ├─ known_scanner_inventory.csv
                    │      └─ config/scanners/feeds/*.json (BinaryEdge, etc.)
                    │
                    ├─▶ FALLBACK: SQLite (STINGAR_STORAGE_BACKEND=sqlite)
                    │
                    └─▶ sync_queue ──▶ POST /api/v1/sync/events ──▶ central
                                                              │
                                                              └─▶ same ES indices (when ES backend)
                                                              └─▶ llm_gateway (global_joined only)

Analyst query: GET /api/v1/sessions?q=severity:>=high&hours=24
Kibana: index pattern `stingar-*` (see es/dashboards/README.md)
```

**Unit of work:** enriched honeypot session/event (indexed by session_id or content hash)  
**Primary store:** Elasticsearch with ILM, Kibana-ready index templates, session query language  
**Secondary store:** SQLite only when `STINGAR_STORAGE_BACKEND=sqlite` (tests, air-gapped dev)  
**Enrichment depth:** one deterministic `build_intelligence_summary()` per new IP; documents denormalize `effective_severity` and `effective_signals` for ES filtering

### c2-engine (reference)

```
honeypot(+plugin) ─:24224─▶ fluentd ─▶ redis ─▶ ANNOTATOR ─▶ ES (sessions + objects)
                                    │   ▲
                    enrich jobs ────┘   └─ Tier-0 lookups
                         ▼
              LOCAL ENRICHER (Tier 1 fast / Tier 2 deep) ─ verdicts ─┘
     contribute (opt-in, egress-filtered) ─▶ GLOBAL ─▶ replica sync back down
```

**Unit of work:** session at ingest + derived objects (payload, infra, playbook, edge)  
**Primary store:** Elasticsearch with ILM, Kibana views, session query language  
**Enrichment depth:** Tier 0 (lookups) → Tier 1 (fast) → Tier 2 (deep); ADR-023 local-only per registry

### Store alignment (post-migration)

| Layer | c2-engine | threat-intel-agent | Aligned? |
|---|---|---|---|
| Session/events index | `stingar-*` + `hp_data.enrichment` | `stingar-*` + `hp_data.enrichment` stub | ✅ Aligned (daily suffix) |
| Scanner Tier-0 data | `intel-feeds` index (ADR-028) | CSV + feed JSON snapshots | ⚠️ Same role; different storage until port |
| IP summary cache | object indices | `intel-summaries` | ⚠️ Different index; same upsert pattern |
| ILM | Per-stream policies (180d events) | `stingar-policy` (180d delete) | ✅ Same retention intent |
| Query language | §8d field aliases on `stingar-*` | §8d subset on `stingar-*` | ✅ Same parser shape |
| Object indices | payloads, infra, playbooks, edges | Not yet — clusters in API response only | ❌ c2-engine owns |
| Offline queue | Fluentd disk buffer | `sync_queue` SQLite | ⚠️ Different mechanism |

---

## Known scanner inventory & vendor feeds

Automated scanner maintenance (parallel agent work) replaces the static-only `default_scanners.json` path when `known_scanner_inventory.csv` exists.

### Data sources

| Source | Path | Role |
|---|---|---|
| CSV inventory | `config/scanners/known_scanner_inventory.csv` | Analyst-maintained vendor rows: vendor, scanner_type, cidr, source_url, last_verified, confidence |
| Static JSON fallback | `config/scanners/default_scanners.json` | Used only when CSV is absent |
| Dynamic feed snapshots | `config/scanners/feeds/*.json` | Large rotating feeds (e.g. BinaryEdge ~4.8k CIDRs) — too big for CSV rows |
| Client overrides | `config/clients/{client_id}_scanners.json` | Per-deployment CIDR additions |

### Loading pipeline (`threat_intel/scanners.py`)

1. `load_scanner_inventory()` reads the CSV (all rows, including pending vendors without CIDRs).
2. `load_scanner_feed_snapshots()` expands `config/scanners/feeds/*.json` into classifiable rows.
3. `inventory_to_scanner_entries()` groups by vendor slug; only **high/medium-confidence** CIDRs enter the match table.
4. `ScannerRegistry.from_inventory()` merges CSV + feed snapshots + client JSON.
5. `classify_known_scanner()` / `ScannerRegistry.classify_ip()` — longest-prefix CIDR wins.

### Maintenance (`threat_intel/scanner_inventory_maintenance.py`)

Auto-managed vendor feeds (official pages/APIs):

- **Censys** — documented range parsing from vendor page
- **Cortex Xpanse (Palo Alto)** — live parse with documented CIDR fallback
- **ONYPHE** — probe URL checks + documented fallback ranges
- **LeakIX** — range extraction
- **BinaryEdge** — API minions list → `config/scanners/feeds/binaryedge.json` (not inlined in CSV)

Manual / pending vendors tracked separately:

- **Shadowserver** — manual CSV rows (`MANUAL_VENDORS`)
- **Pending:** Shodan, Rapid7 Sonar, Google/Microsoft/AWS/Akamai/Cloudflare research ranges (URL reachability checked, CIDR TBD)

### Operations

```bash
# CLI refresh (also agent tool + central API)
python3 -m threat_intel.scanner_inventory_maintenance
python3 -m threat_intel.scanner_inventory_maintenance --dry-run

# Central API
curl -X POST -H "Authorization: Bearer $CENTRAL_API_KEY" \
  'http://127.0.0.1:8080/api/v1/scanners/refresh?dry_run=false'

curl -H "Authorization: Bearer $CENTRAL_API_KEY" \
  'http://127.0.0.1:8080/api/v1/scanners/inventory?client_id=example-stingar-01'
```

**GitHub Actions:** `.github/workflows/scanner-inventory-refresh.yml` — weekly Monday 06:00 UTC refresh, commits CSV + feed snapshots.

**Agent tools in `main.py`:** `list_scanner_inventory`, `refresh_scanner_inventory` (16 tools total).

### c2-engine porting note

This maps directly to c2-engine **Tier-0** and ADR-028 `intel-feeds`:

- CSV + feed snapshots → local `intel-feeds`-style index or inline lookup table in the annotator
- `refresh_scanner_inventory()` → background sync job (same family as abuse.ch feed sync in `reason/intel.py`)
- Only high/medium-confidence documented ranges classify at ingest — matches c2-engine's FP discipline

### Tests

- `tests/test_scanner_inventory.py` — classification, longest-prefix, pending vendors
- `tests/test_scanner_inventory_maintenance.py` — feed parsers, merge logic, dry-run refresh

---

## Elasticsearch primary store — implementation review

### New modules

| Module | Role |
|---|---|
| `threat_intel/elasticsearch/client.py` | urllib ES client (no elasticsearch-py dep; mirrors c2-engine pattern) |
| `threat_intel/elasticsearch/schema.py` | Loads templates/ILM from `es/` |
| `threat_intel/elasticsearch/intelligence_cache.py` | `intel-summaries` upsert cache (`IntelligenceCacheBackend`) |
| `threat_intel/elasticsearch/document_store.py` | Indexes enriched docs; session search |
| `threat_intel/elasticsearch/session_query.py` | Query tokenizer → ES bool query |
| `threat_intel/storage.py` | Backend selection (`elasticsearch` default, `sqlite` fallback) |
| `es/templates/stingar-enriched.json` | Strict mapping for Attack Analysis queries |
| `es/templates/intel-summaries.json` | IP summary object index |
| `es/ilm/stingar-enriched-policy.json` | Hot → warm → delete @ 180d |
| `es/dashboards/README.md` | Kibana view guidance |

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `STINGAR_STORAGE_BACKEND` | `elasticsearch` | Primary store selector |
| `ELASTICSEARCH_URL` | — | Full cluster URL (overrides host/port) |
| `ELASTICSEARCH_HOST` | `127.0.0.1` | ES host |
| `ELASTICSEARCH_PORT` | `9200` | ES port |
| `STINGAR_STORAGE_BACKEND=sqlite` | — | Dev/test fallback |

### API

```bash
# Health — shows storage backend + ES reachability
curl http://127.0.0.1:8080/health

# Session query (Attack Analysis equivalent)
curl -H "Authorization: Bearer $CENTRAL_API_KEY" \
  'http://127.0.0.1:8080/api/v1/sessions?q=severity:>=high&hours=24&client_id=example-stingar-01'
```

Supported query fields: `src_ip`, `signal`, `severity`, `family`, `honeypot`, `verdict`, `client_id`, bare IP/sha256 routing.

### Strengths

- Matches c2-engine ADR-013 ("ES everywhere for intel") without waiting for full registry build.
- Strict index templates prevent mapping explosion.
- Documents carry `hp_data.enrichment.effective_*` fields — forward-compatible with MVP-DESIGN.md stamp.
- Enrichment pipeline writes to ES automatically via `enrichment_core` (`es_stats` in response).
- Tests use SQLite fallback; session query has dedicated unit tests.

### Remaining ES gaps

| # | Gap | Recommendation |
|---|---|---|
| E1 | ~~Index prefix divergence~~ | — | **Resolved** — daily indices now `stingar-YYYY-MM-DD` |
| E2 | No bundled Kibana NDJSON dashboards | Port/adapt `c2-engine/es/dashboards/` |
| E3 | ~~ES errors silent in webhook~~ | — | **Resolved** — `storage_warnings` + `es_stats` in webhook response |
| E4 | ~~Sanitize only on sync~~ | — | **Resolved** — `sanitize_document()` before ES index in `enrichment_core` |
| E5 | No `global-*` replica indices yet | North-star ADR-025; not MVP |
| E6 | Cluster/incident objects not materialized as ES docs | Add rollup index or compute via ES aggregations |

---

## Principle alignment

| Principle | c2-engine (ADR) | threat-intel-agent | Match |
|---|---|---|---|
| Facts at sensor, interpretations at deployment | ADR-015/027 | Interpretations run locally; written to ES at deployment | ✅ |
| ES as intel store | ADR-013/022 | Primary store = ES | ✅ |
| Enrichment local-only per registry | ADR-023 | Local enrich; ES is local deployment store | ✅ |
| Pull not gated on contribute | ADR-019 | `global_joined` gates LLM only | ✅ |
| No WAN on ingest path | ingest design | ES write is local; sync is optional WAN | ⚠️ Partial |
| One writer per field family | ES field ownership | Single writer per index; taxonomy/policy merged pre-write | ⚠️ Improved |
| Session query language | DATA-AND-VIEWS §8d | Implemented subset | ✅ Partial |
| Opt-in federation, egress-filtered | contribute layer | `evaluate_shareability()` before sync | ✅ |

---

## What was implemented well

### 1. Policy layer (`safelist`, `sharing_policy`, `policy_engine`)

Unchanged — still the strongest port candidate for c2-engine Tier-0 and egress filter.

### 2. Hybrid client flow (`stingar/client.py`)

Local enrich → ES index → optional sync. IP dedup uses **`intel-summaries` / intelligence cache only** (no `.stingar_seen_ips.json`). Sync queue remains for north-star federation prototype.

### 3. Elasticsearch primary store (new)

Replaces SQLite-as-primary. Intelligence dedup via `intel-summaries` mget; sessions searchable without re-enrichment.

### 4. Taxonomy + session signals

`effective_signals` denormalized at index time from taxonomy tags — feeds both ES filters and future `hp_data.enrichment.signals`.

### 5. Global LLM gateway (`central/llm_gateway.py`)

Tier-2 slot unchanged; results should eventually write to payload/session `enrichment.revisions[]` (ADR-028).

### 6. Known scanner inventory + feed maintenance (new)

CSV-driven registry with automated vendor feed refresh — strongest **Tier-0 port package** for c2-engine. BinaryEdge-scale feeds correctly kept out of CSV rows via JSON snapshots.

---

## Issues and risks

### Critical / high

| # | Issue | Status | Notes |
|---|---|---|---|
| H1 | **Not on STINGAR v2.3 ingest path** | Open | Port into c2-engine inline engine; ES + scanner modules ready |

### Medium

| # | Issue | Recommendation |
|---|---|---|
| M1 | Single-tier enrichment (no Tier 0/1/2 split) | Split ES writes: inline stamp vs background enricher jobs |
| M2 | Sync queue not ES-backed | Keep for offline federation prototype; Fluentd buffer is prod path |
| M3 | SQLite ResourceWarning in tests | Context managers on SQLite connections |
| M4 | Kibana dashboards not shipped | Import c2-engine NDJSON or build Attack Analysis data view |
| M5 | LLM gateway has no rate limiting | Per-client token bucket |

---

## c2-engine overlap map (updated)

| threat-intel-agent module | c2-engine equivalent | Recommendation |
|---|---|---|
| `threat_intel/elasticsearch/*` | `engine/src/c2engine/elastic/*` + `es/` | **Merge** — unify templates; this repo's session query ports to annotator |
| `es/templates/stingar-enriched.json` | `stingar-*` template (MVP-DESIGN) | **Combine** — merge mappings into one template at port time |
| `intel-summaries` index | `intel-feeds` + object indices | **Replace** long-term; keep as IP cache until registry lands |
| `threat_intel/scanners.py` + CSV + feed snapshots | Tier-0 annotator + `intel-feeds` | **Port first** — maintenance tooling included |
| `threat_intel/scanner_inventory_maintenance.py` | Background feed sync job | **Port** — maps to ADR-028 feed sync |
| `config/scanners/feeds/binaryedge.json` | Dynamic scanner feed snapshot | **Same pattern** as large feed indices |
| `threat_intel/safelist.py` | Tier-0 + blocklist suppress | **Port** |
| `threat_intel/policy_engine.py` | Egress filter + sanitizer | **Port** |
| `threat_intel/cache.py` (SQLite) | ES only in prod | **Dev fallback only** |
| `stingar/sync_queue.py` | Fluentd forward + replica sync | **Replace** at north star |
| `central/llm_gateway.py` | Tier 2 enricher | **Keep** |

---

## Recommended roadmap (updated)

### Phase A — ES + scanner production hardening (in progress)

1. ~~Rename index to `stingar-*`~~ ✅
2. ~~Deprecate `.stingar_seen_ips.json`~~ ✅
3. ~~Sanitize before ES index~~ ✅
4. ~~Central sync re-validation~~ ✅
5. Bundle Kibana Attack Analysis data view
6. Extract more enrichment functions from `main.py`

### Phase B — Port into c2-engine inline engine (2–4 weeks)

1. Move ES writer + session query into `engine/` between Fluentd and ES
2. Port `ScannerRegistry` + `refresh_scanner_inventory` as Tier-0 + background job
3. Stamp `hp_data.enrichment.src` from scanner classification
4. Tier-0: safelist + taxonomy signals
5. Tier-1: IP reputation background pass
6. CIF egress via existing STINGAR output

### Phase C — North star registry (deferred)

1. Observation streams + transforms (ADR-029)
2. `global-*` replicas (ADR-025)
3. Retire HTTP sync queue

---

## Bottom line

**Elasticsearch is now the primary store** — ILM-managed session indices, object-style summary cache, session query API, and Kibana-ready templates. This closes the largest structural gap vs c2-engine's data model (ADR-013) while keeping the HTTP ingest path as the main remaining divergence.

**Best path forward:** Use this repo's ES layer (`threat_intel/elasticsearch/`, `es/templates/`) as the **write target when porting into c2-engine's inline engine**. Unify index naming to `stingar-*`, port policy modules to Tier-0, and retire SQLite-as-primary except for unit tests.

See also: **[C2_ENGINE_INTEGRATION.md](./C2_ENGINE_INTEGRATION.md)** for branch access and MVP vs north-star timeline.
