# Architecture Decision Log

Lightweight ADRs documenting design choices for **threat-intel-agent**. Status: **Accepted**.

Format: Context → Decision → Consequences.

---

## ADR-001 — Local-first enrichment

**Context:** STINGAR honeypots generate continuous IP telemetry. Enrichment must work when central is unreachable, and interpretations should reflect local deployment context (safelist, scanner tables, policy).

**Decision:** Every STINGAR node enriches locally first via `HybridEnrichmentClient` → `local_pipeline` → `enrichment_core`. Central receives pre-enriched documents via sync; it does not re-run the full pipeline on sync ingest.

**Consequences:**
- Honeypot triage works offline
- Each deployment can have different scanner/safelist overrides
- Central merge path is simpler (cache upsert + ES index)
- Duplicate enrichment logic is avoided by sharing `threat_intel/` library

---

## ADR-002 — Elasticsearch primary store with SQLite fallback

**Context:** Enriched sessions and IP summaries need durable storage, analyst query, and ILM-managed retention. Tests and air-gapped dev need zero external dependencies.

**Decision:** Default production backend is Elasticsearch (`stingar-*` daily indices + `intel-summaries` upserts). Set `STINGAR_STORAGE_BACKEND=sqlite` for tests and offline dev.

**Consequences:**
- Session query API requires ES
- SQLite remains for unit tests only in CI
- Index templates and ILM policy live in `es/`
- Kibana can attach to `stingar-*` index pattern

---

## ADR-003 — Severity and investigation as separate outputs

**Context:** Known scanners often have high abuse scores. Treating abuse score alone as escalation criteria produces false-positive incident storms.

**Decision:** Produce two independent outputs: **severity** (risk score from reputation + context) and **investigation classification** (analyst workflow category). Scanner match can yield HIGH severity but `known_scanner` investigation class with LOW priority.

**Consequences:**
- Analyst dashboards can filter on investigation class, not raw severity
- Safelist caps severity without hiding scanner identity
- Both outputs are stored on ES documents and in intelligence cache

---

## ADR-004 — CSV + feed-snapshot scanner inventory

**Context:** Scanner vendor CIDR ranges change frequently. Small vendors fit CSV rows; large feeds (BinaryEdge ~4.8k CIDRs) do not.

**Decision:** Maintain `known_scanner_inventory.csv` for analyst-curated vendor rows plus `config/scanners/feeds/*.json` for large dynamic snapshots. Auto-refresh via `scanner_inventory_maintenance.py` and weekly CI.

**Consequences:**
- Longest-prefix CIDR match via `ScannerRegistry.from_inventory()`
- Only high/medium-confidence ranges enter the match table
- Feed refresh is decoupled from code deploys
- Client overrides merge via `config/clients/{client_id}_scanners.json`

---

## ADR-005 — Policy-gated sync with central re-validation

**Context:** Hybrid deployments must not leak private destination IPs, sensor IDs, or internal-tagged events to a central aggregator. Clients could be misconfigured or compromised.

**Decision:** Local nodes sanitize and evaluate shareability before sync. Central re-runs `evaluate_shareability()` on every document in `POST /api/v1/sync/events`. Returns 403 if all documents rejected.

**Consequences:**
- Defense-in-depth on federation boundary
- Default policy strips `destination.ip`, `event.original`, `stingar.sensor_id`
- Private destination CIDRs blocked even after field stripping
- Offline queue stores already-sanitized payloads

---

## ADR-006 — LLM global-only on central

**Context:** Claude agent investigations are expensive, require API keys, and are not needed for high-volume honeypot ingest. Local nodes should not hold Anthropic credentials for production ingest.

**Decision:** LLM access only via `POST /api/v1/llm/investigate` on central, gated by `global_joined: true` in client sharing policy. Local nodes run deterministic enrichment only.

**Consequences:**
- `STINGAR_ENABLE_LLM=false` on nodes as extra guard
- Agent loop stays in `main.py`; not on hot ingest path
- Joined clients opt in explicitly via policy file

---

## ADR-007 — Extract deterministic enrichment from main.py

**Context:** `enrichment_core` previously imported `main.py` via `_import_main()`, pulling in Anthropic client, agent tools, and module-level side effects on every pipeline run.

**Decision:** Move deterministic functions to `threat_intel/` modules (`lookups`, `severity`, `investigation`, `campaign`, `documents`, `incidents`, `intelligence_summary`). `main.py` retains agent loop + re-exports only.

**Consequences:**
- Pipeline imports are clean; no startup prints on enrich
- Agent and production paths share the same lookup backends
- `main.py` reduced from ~2,500 to ~1,100 lines

---

## ADR-008 — HTTP webhook ingest (Fluent Bit path deferred)

**Context:** STINGAR production nodes need local durable ingest. c2-engine uses Fluentd forward on `:24224`; we intentionally **avoid Fluentd** and align internally with **Fluent Bit**. This repo shipped HTTP webhook ingest first to unblock enrichment development.

**Decision:** Ingest via HTTP webhook (`stingar/webhook_listener.py`) and optional direct central webhooks for now. Production ingest target is **Fluent Bit → STINGAR message cube → enrichment worker** (H2 in ROADMAP), not Fluentd inline annotation.

**Consequences:**
- Works with any honeypot that can POST JSON today
- HTTP remains supported for dev/testing after H2 lands
- Message cube becomes the local durability boundary (decouples capture from enrich)
- ES enrichment modules are ready to consume from the cube without c2-engine Fluentd port

---

## Related docs

- [ARCHITECTURE.md](./ARCHITECTURE.md) — how decisions manifest in the system
- [ROADMAP.md](./ROADMAP.md) — open work including H2 Fluent Bit + message cube ingest
- [C2_ENGINE_INTEGRATION.md](./C2_ENGINE_INTEGRATION.md) — cross-repo porting (separate concern)
