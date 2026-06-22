# Roadmap

Open work and known gaps for threat-intel-agent.

Last updated from [CODE_REVIEW.md](./CODE_REVIEW.md) engineering review.

## Status summary

| Area | Status |
|---|---|
| Hybrid local-first flow | Done |
| Elasticsearch primary store | Done |
| Scanner inventory + feed maintenance | Done |
| Policy / safelist / sync defense-in-depth | Done |
| Deterministic enrichment modularization (H1) | Done |
| Fluent Bit–compatible local ingest (H2) | Not started |
| Tier 0/1/2 enrichment split | Not started |
| Kibana dashboards bundled | Not started |
| LLM rate limiting | Not started |

---

## High priority

### H2 — Fluent Bit–compatible local ingest (no Fluentd)

**Problem:** Current ingest is HTTP webhook → local enrich. That works for dev and hybrid sync, but production STINGAR nodes need a **local durable ingest path** that fits our internal stack (Fluent Bit, not Fluentd) and decouples honeypot event capture from enrichment latency.

**Goal:** Avoid Fluentd entirely. Provide an alternative that:

1. Accepts honeypot telemetry through a **Fluent Bit–compatible** input/output path (same ecosystem we run internally).
2. Writes a **local copy** of each event into a **STINGAR message cube** — a local durable buffer on the node before enrichment runs.
3. Lets the enrichment pipeline consume from the message cube asynchronously (Tier-0 stamp fast, heavier enrichment behind).
4. Keeps HTTP webhook as a fallback for testing and integrations that cannot emit through Fluent Bit.

**Proposed shape:**

```
honeypot / sensor
    │
    ▼
Fluent Bit (local) ──▶ STINGAR message cube (local durable buffer)
                              │
                              ▼
                    enrichment worker / HybridEnrichmentClient
                              │
                              ├─▶ ES (stingar-*)
                              └─▶ optional sync to central
```

**Plan:**
- Define message cube schema and retention (local spool; survives restarts; backpressure when enricher is slow).
- Add Fluent Bit output plugin or forward target that lands events in the cube (replace Fluentd `:24224` forward pattern).
- Wire cube consumer to existing `local_pipeline` / `enrichment_core` (reuse current enrichment modules).
- Document Fluent Bit config snippets alongside [DEPLOYMENT.md](./DEPLOYMENT.md).

**Non-goals:** Fluentd inline engine, c2-engine Fluent forward port, or `:24224` msgpack ingest.

**Reference:** [C2_ENGINE_INTEGRATION.md](./C2_ENGINE_INTEGRATION.md) describes c2-engine's Fluentd path — we are **not** adopting that; this H2 is the threat-intel-agent alternative.

---

## Medium priority

### M1 — Tier 0/1/2 enrichment split

**Problem:** Single batch path runs full `build_intelligence_summary()` per new IP. No inline Tier-0 stamp vs background Tier-1/2 jobs.

**Plan:**
- Tier 0: scanner + safelist stamp at ingest (fast)
- Tier 1: IP reputation background pass
- Tier 2: deep enrichment / LLM (on demand)

### M2 — Sync queue not ES-backed

**Problem:** Offline queue uses SQLite (`data/sync_queue.db`). Production may need a durable local buffer aligned with the H2 message cube.

**Plan:** Keep SQLite sync queue for hybrid federation prototype. Long-term, central-destined payloads may spool through the same **STINGAR message cube** local buffer as ingest events (single local durability layer per node).

### M3 — SQLite ResourceWarning in tests

**Problem:** Unit tests emit `ResourceWarning: unclosed database` for SQLite connections.

**Plan:** Add context managers on SQLite cache connections in `threat_intel/cache.py`.

### M4 — Kibana dashboards not shipped

**Problem:** ES index templates exist; no bundled NDJSON dashboards for Attack Analysis view.

**Plan:**
- Build data view for `stingar-*` index pattern
- Port or adapt dashboard definitions
- Document import steps in `es/dashboards/README.md`

### M5 — LLM gateway rate limiting

**Problem:** `POST /api/v1/llm/investigate` has no per-client token bucket or cost guard beyond agent `MAX_TURNS`.

**Plan:** Add rate limit middleware keyed by `client_id`.

---

## Test coverage gaps

Current suite: **21 tests** covering hybrid integration, scanner inventory, session query, sync shareability.

| Area | Coverage |
|---|---|
| Hybrid client + policy | Good |
| Scanner CSV + feeds | Good |
| Session query parser | Good |
| Sync 403 defense-in-depth | Good |
| ES integration (live cluster) | None (mocked/unavailable in CI) |
| Webhook listener E2E | None |
| LLM gateway | None (requires API key) |
| sync_worker drain loop | None |

---

## Completed (recent)

- Elasticsearch primary store with `stingar-*` daily indices
- Intelligence cache dedup (removed `.stingar_seen_ips.json`)
- Central sync re-validation (403 if all rejected)
- Sanitize before ES index write
- Scanner inventory maintenance + weekly CI refresh
- H1: extract enrichment from `main.py` into `threat_intel/` modules

---

## Related docs

- [DECISIONS.md](./DECISIONS.md) — rationale for current architecture
- [CODE_REVIEW.md](./CODE_REVIEW.md) — detailed engineering review with c2-engine comparison
- [ARCHITECTURE.md](./ARCHITECTURE.md) — current system design
