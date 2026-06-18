# c2-engine Integration Guide

How to give Cursor (and teammates) access to **c2-engine** for merge reviews, and how **threat-intel-agent** maps onto the active STINGAR plan (ADR-033 MVP + north-star registry).

---

## How to give the agent access to c2-engine

You already have everything needed on GitLab. The branch **`origin/c2-engine`** on `gitlab.oit.duke.edu:codeplus2026/ai_tools` was fetched successfully from this workspace — no extra credentials required if your SSH key works for GitLab.

### Option A — Git fetch only (lightest; good for reviews)

From `threat-intel-agent`:

```bash
git fetch origin c2-engine
```

The agent can read any file without checking out the branch:

```bash
git show origin/c2-engine:c2-engine/docs/MVP-DESIGN.md
git ls-tree -r --name-only origin/c2-engine:c2-engine/engine/
```

**Pros:** No workspace clutter, no branch switch.  
**Cons:** Can't run c2-engine tests or import both trees side-by-side in one Python path without more setup.

### Option B — Git worktree (best for implementation)

Adds a second folder on disk, same repo, different branch:

```bash
cd /Users/rudhmilahoque/Desktop/threat-intel-agent
git fetch origin c2-engine
git worktree add ../c2-engine-worktree origin/c2-engine
```

Then in Cursor: **File → Add Folder to Workspace** → select `../c2-engine-worktree`.

You now have:

| Folder | Branch | Path on branch |
|---|---|---|
| `threat-intel-agent/` | `threat-enrich-agent` | repo root |
| `c2-engine-worktree/` | `c2-engine` | `c2-engine/` subdirectory |

**Pros:** Full edit/run/test on both codebases; agent sees both in one workspace.  
**Cons:** Two folders to manage; remove with `git worktree remove ../c2-engine-worktree`.

### Option C — Submodule or subtree (long-term monorepo)

If Duke wants one repo long-term:

```bash
# submodule (keeps separate history)
git submodule add -b c2-engine git@gitlab.oit.duke.edu:codeplus2026/ai_tools.git vendor/c2-engine

# OR subtree merge (single history — heavier)
git subtree add --prefix=c2-engine origin c2-engine --squash
```

Use when you're ready to **merge branches permanently**, not for a first review.

### Option D — Paste / attach in chat

What you did with DECISIONS + DATA-AND-VIEWS works for architecture questions. For file-level porting, Options A or B are better.

### Option E — Open c2-engine as the primary workspace

Clone fresh and open only the c2-engine branch:

```bash
git clone -b c2-engine git@gitlab.oit.duke.edu:codeplus2026/ai_tools.git stingar-c2-engine
cd stingar-c2-engine/c2-engine
```

Then copy or submodule `threat-intel-agent` modules in as you port.

---

## What the agent can already see (verified)

```
origin/c2-engine/
├── c2-engine/
│   ├── README.md
│   ├── docs/          ← DECISIONS, DATA-AND-VIEWS, MVP-DESIGN, MIGRATION, …
│   ├── engine/        ← v1 inline engine (porting seed)
│   ├── sensor/        ← output_stingar Cowrie overlay
│   ├── deploy/        ← docker-compose, fluentd, nginx
│   ├── es/            ← index templates, Kibana dashboards
│   └── prototype/     ← Attack Analysis UI prototype
└── (other ai_tools root files)
```

Key engine modules (from `MIGRATION.md`):

| v1 module | Role |
|---|---|
| `services/ingest/forward.py` | Fluent msgpack decode, inline ingest |
| `pipeline/extract/{hosts,chains,files}.py` | C2 / payload extraction |
| `services/reason/intel.py` | abuse.ch bulk feeds → Tier-0 matching |
| `services/reason/vt.py` | Per-hash VT cache |
| `services/reason/engine.py` | Evidence ladder, stage, HASSH toolkit |
| `services/feed/server.py` | C2 blocklist export |

---

## The two timelines (don't merge the wrong one)

c2-engine has **two** plans. threat-intel-agent must align to the **active** one first.

| Plan | ADR | Timeline | Federation |
|---|---|---|---|
| **MVP (active)** | ADR-033 | ~2–3 weeks | CIF only — no sync protocol |
| **Registry north star (deferred)** | ADR-022…032 | ~6 months | fluent forward up + replica sync down |

### ADR-033 MVP (build this first)

- Engine sits **inline** between Fluentd and ES (same as v1).
- Stamps **`hp_data.enrichment`** on every session before index.
- Thin rollups: `c2s`, `payloads` — relationships from stamped **events**, not arrays.
- Global sharing = **CIF** (existing STINGAR path). No `POST /api/v1/sync/events` equivalent yet.
- **`hp_data.enrichment` is the load-bearing contract** — identical in MVP and north star; UI survives migration.

### North star (port threat-intel-agent policy layer here later)

- Redis-decoupled annotator + enricher (ADR-027/028).
- Per-entity observation streams + ES transforms (ADR-029).
- `intel-feeds` index for Tier-0 (ADR-028).
- `global-*` replica indices + cursor sync (ADR-025).
- Community verdicts up, objects down (ADR-031).
- Egress filter on fluent forward (ADR-024) — **this is where sharing policy belongs long-term**.

**Implication:** threat-intel-agent's `sync_queue`, `HybridEnrichmentClient`, and central FastAPI sync path are **prototypes** of north-star federation — useful design reference, **not** the MVP integration surface. For MVP, port into **`c2-engine/engine/`** and emit CIF.

---

## Architecture: where each repo belongs

```
                    threat-intel-agent TODAY              c2-engine MVP (ADR-033)
                    ────────────────────────              ──────────────────────
Honeypot ──────────▶ webhook_listener :8090              honeypot + output_stingar
                         │                                    │
                         ▼                                    ▼
                    local_pipeline                         Fluentd :24224
                    (Elasticsearch)                             │
                         │                                    ▼
                         ▼                              C2-ENGINE (inline)
                    policy_engine                               │
                         │                          hp_data.enrichment stamp
                         ▼                                    ▼
                    sync_queue ──HTTP──▶ central              Elasticsearch
                                         (same ES)                   │
                    scanner CSV + feeds ──▶ Tier-0 lookup      CIF out (community)
```

**Production target:** left column collapses into the right column's inline engine. Central LLM gateway stays a **separate Tier-2 service** until north-star federation exists.

---

## Known scanner inventory (threat-intel-agent)

Parallel agent work added a **maintained scanner data plane** that c2-engine Tier-0 should consume wholesale.

### Architecture

```
Official vendor pages/APIs
        │
        ▼
scanner_inventory_maintenance.py  ──▶  known_scanner_inventory.csv
        │                              config/scanners/feeds/*.json
        ▼
ScannerRegistry.from_inventory()
        │
        ├─▶ classify_known_scanner() at enrichment time
        └─▶ hp_data.enrichment.src (when ported to c2-engine annotator)
```

### Files

| File | Purpose |
|---|---|
| `config/scanners/known_scanner_inventory.csv` | ~150 rows — vendor, type, CIDR, source_url, last_verified, confidence |
| `config/scanners/feeds/binaryedge.json` | BinaryEdge minions snapshot (~4.8k CIDRs) — dynamic feed, not CSV rows |
| `config/scanners/default_scanners.json` | Legacy static fallback if CSV missing |
| `threat_intel/scanners.py` | CSV + feed snapshot loader, `ScannerRegistry`, `list_scanner_inventory()` |
| `threat_intel/scanner_inventory_maintenance.py` | Feed fetchers, merge, weekly refresh |
| `.github/workflows/scanner-inventory-refresh.yml` | Scheduled CI refresh |

### Vendor coverage

| Vendor | Maintenance mode | Classification |
|---|---|---|
| Censys | Auto feed parse | high/medium CIDRs in CSV |
| Cortex Xpanse | Auto + documented fallback | CSV |
| ONYPHE | Auto + documented fallback | CSV |
| LeakIX | Auto feed parse | CSV |
| BinaryEdge | API → JSON snapshot | dynamic feed file |
| Shadowserver | Manual CSV rows | manual |
| Shodan, Rapid7, cloud research | Pending — URL checked, CIDR TBD | pending rows |

### APIs & tools

```bash
GET  /api/v1/scanners/inventory     # full spreadsheet + coverage stats
POST /api/v1/scanners/refresh       # ?dry_run=true|false
GET  /api/v1/scanners/table         # flat CIDR table for analysts
```

Agent tools: `list_scanner_inventory`, `refresh_scanner_inventory` in `main.py`.

### c2-engine mapping (MVP Tier-0)

| threat-intel-agent | c2-engine target |
|---|---|
| `known_scanner_inventory.csv` | Seed for local lookup table / future `intel-feeds` scanner slice |
| `config/scanners/feeds/*.json` | Same pattern as large rotating feeds — do not inline in CSV |
| `refresh_scanner_inventory()` | Background job alongside `reason/intel.py` abuse.ch sync (ADR-028) |
| `classify_known_scanner()` | Annotator inline lookup: `malicious_scanner` / `known_scanner` signal |
| Confidence gating (high/medium only) | Same FP discipline as c2-engine Tier-0 |

When porting, copy **`scanner_inventory_maintenance.py` + tests** with the registry — the maintenance loop is as important as the match table.

---

## Module porting map (threat-intel-agent → c2-engine)

### MVP phase (weeks 1–3) — inline engine diffs

| threat-intel-agent | Port into c2-engine | MVP mechanism |
|---|---|---|
| `threat_intel/scanners.py` + CSV + `feeds/*.json` | Tier-0 lookup in inline stamp | Match `src_ip` → scanner signal; stamp `hp_data.enrichment.src` |
| `scanner_inventory_maintenance.py` | Background feed sync (ADR-028 family) | Weekly vendor refresh; BinaryEdge → JSON snapshot |
| `threat_intel/safelist.py` | Tier-0 lookup | `signals: ["safelisted"]`; suppress blocklist CIF emit for matched CIDRs |
| `threat_intel/taxonomy.py` | `hp_data.enrichment.signals[]` | Map tags to MVP signal keywords: `c2_attack`, `novel_payload`, `malicious_scanner`, `potential_zero_day` (UI label for `novel_payload`) |
| `threat_intel/sharing_policy.py` | **CIF egress only for MVP** | Gate `CONTRIBUTE_INDICATORS` — strip private dst IPs from CIF payloads (ADR-019 channel toggle) |
| `main.py` Tier-1 tools (AbuseIPDB, GreyNoise) | Background pass in engine container | Same slot as `reason/vt.py` + `reason/intel.py` — **not on ingest hot path** (ADR-028) |
| `threat_intel/elasticsearch/*` | `engine/src/c2engine/elastic/*` | **Merge** — `stingar-*` indices now aligned |
| `stingar/client.py` (intel cache dedup) | inline engine dedup | **Resolved locally** — no separate seen-IP JSON |
| `central/server.py` `/api/v1/sync/events` | CIF for MVP; replica sync north star | **Hardened** — central re-validates sharing policy |
| `central/llm_gateway.py` | Optional background Tier-2 | Call only when `global_joined`; write explanation to payload rollup |

### MVP `hp_data.enrichment` extension (proposed)

Align with MVP-DESIGN.md and add blocks threat-intel-agent already computes:

```jsonc
"hp_data": {
  "enrichment": {
    "version": "mvp-1",
    "c2s": [ /* existing MVP */ ],
    "payloads": [ /* existing MVP */ ],
    "playbook_hash": "…",
    "signals": ["c2_attack", "malicious_scanner"],

    // PORT from threat-intel-agent (new for MVP+)
    "src": {
      "ip": "203.0.113.10",
      "verdict": "malicious",
      "scanner_id": "cortex-xpanse",
      "safelisted": false,
      "severity": "LOW"
    },
    "as_of": {
      "local_rules": "scanner-inventory-2026-06-01",
      "global_sync": null
    },
    "status": "complete"
  }
}
```

Severity ladder (DATA-AND-VIEWS §8c) replaces auth-derived severity — threat-intel-agent's `calculate_enriched_severity` feeds **`effective_signals`**, not raw auth success.

### North-star phase (months) — registry federation

| threat-intel-agent | North-star home | ADR |
|---|---|---|
| `policy_engine.evaluate_shareability()` | Fluentd egress filter before forward | ADR-024 |
| `policy_engine.sanitize_document()` | Egress field profile (explicit allowlist) | ADR-024 |
| `sync_queue` + `sync_worker` | Replace with replica sync client | ADR-025 |
| `central/server.py` `/api/v1/sync/events` | Replace with cursor pull of `global-*` indices | ADR-025 |
| `threat_intel/cache.py` | Replace with ES object docs + `intel-feeds` | ADR-028 |
| `llm_gateway.py` | Tier-2 enricher job + `CONTRIBUTE_ENRICHMENT` | ADR-031/032 |

**Federation wire format:** Not defined for MVP. North star uses **fluent forward (msgpack records)** up and **cursor-based object doc sync** down — not the JSON batch shape in `stingar/client.py`. When building north star, treat threat-intel-agent's sync payload as a **sketch**, not the contract.

---

## ADR-informed overlap (with your DECISIONS paste)

| ADR | c2-engine rule | threat-intel-agent today | Action |
|---|---|---|---|
| ADR-015 | Normalization at sensor (`output_stingar`) | Webhook accepts ad-hoc JSON | Use sensor plugin envelope; drop custom webhook schema for prod |
| ADR-019 | Pull always-on; contribute opt-in | `global_joined`, sharing policy | ✅ Same intent; wire to CIF toggles first, fluent forward later |
| ADR-023 | Enrichment local-only per registry | Local pipeline + central cache | ✅ Local-first correct; central should not re-enrich on sync (MVP: no sync) |
| ADR-027/028 | Annotator inline; Tier 0 local-only; re-annotate sessions | Batch enrichment after fact | **Move Tier-0 into inline engine**; add reconciler for Tier-1 results |
| ADR-030 | 3 C2 evidence kinds | IP-only classification in `main.py` | c2-engine owns C2 ladder; threat-intel-agent owns scanner/IP reputation |
| ADR-033 | MVP = v1 engine diffs, not full registry | Full hybrid HTTP stack | **Pivot implementation target to `engine/`** |

### Single-writer discipline (DATA-AND-VIEWS §0)

| Field family | Writer | threat-intel-agent conflict |
|---|---|---|
| `hp_data.enrichment` (ingest-time) | Annotator / inline engine | enrichment_core writes equivalent on HTTP path — duplicate |
| `enrichment.revisions[]` | Annotator reconciler | Not implemented here |
| `enrichment.*` on object docs | Local enricher | main.py summary maps here |
| `observed.*` | ES transforms | Not implemented (no observation streams) |
| `global-*` replicas | Sync client only | central/server.py merge — wrong writer for north star |

---

## Concrete next steps for you

### 1. Add c2-engine to this Cursor workspace (recommended)

```bash
cd /Users/rudhmilahoque/Desktop/threat-intel-agent
git fetch origin c2-engine
git worktree add ../c2-engine-worktree origin/c2-engine
```

Then ask the agent: *"Port scanners.py and safelist.py into c2-engine inline Tier-0 using MVP-DESIGN hp_data.enrichment.src"*

### 2. Run c2-engine locally (separate terminal)

```bash
cd ../c2-engine-worktree/c2-engine
# follow deploy/stingar.env.example + deploy/docker-compose.yml
```

Use `python3` — your shell doesn't have bare `python` on PATH (same fix as `stingar.sync_worker`).

### 3. Decide MVP scope for your team

| Include in MVP | Defer |
|---|---|
| Scanner registry + CSV/feeds + maintenance job → inline Tier-0 | HTTP webhook as prod ingest |
| `stingar-*` ES templates + session query | Full central FastAPI server |
| Safelist → inline signals | sync_queue / sync_worker (north star) |
| CIF egress policy (private IP strip) | LLM gateway (unless Tier-2 needed day one) |

### 4. Branch strategy on GitLab

| Branch | Purpose |
|---|---|
| `c2-engine` | STINGAR MVP + registry design |
| `threat-enrich-agent` | IP intel library + policy modules to port |
| Future: `c2-engine-tier0-port` | Cherry-pick `threat_intel/{scanners,safelist,policy_engine}.py` into `engine/` |

Options:
- **Cherry-pick** policy modules as a subtree under `c2-engine/engine/src/c2engine/intel/`
- **PyPI/internal package** — publish `threat_intel` as installable lib both repos depend on
- **Monorepo merge** — subtree merge `threat-enrich-agent` into `c2-engine` branch when port is stable

---

## What still helps (optional)

You already supplied the highest-value docs. For file-level porting PRs, these would complete the picture:

1. `c2-engine/docs/MVP-DESIGN.md` §7 (active diff plan — full section)
2. `c2-engine/engine/src/c2engine/services/ingest/forward.py` (where inline stamp hooks)
3. `c2-engine/sensor/plugins/stingar.py` (event envelope)
4. Example `hp_data` session JSON from production or sample data
5. Which CIF fields Duke strips today (if any egress filter exists)

**Not blocking:** federation wire format — ADR-033 explicitly defers it; MVP uses CIF.

---

## Bottom line

| Question | Answer |
|---|---|
| Can GitLab `c2-engine` branch give the agent those files? | **Yes** — `git fetch origin c2-engine` already works from this repo. |
| Best setup for merge work? | **Git worktree** + add both folders to Cursor workspace. |
| Should threat-intel-agent and c2-engine run in parallel in prod? | **No** — port modules into inline engine; one ingest path. |
| Is threat-intel-agent wasted work? | **No** — scanners/feeds/maintenance, safelist, policy, ES layer, taxonomy, LLM gateway are direct ports |
| Active integration target? | **`c2-engine/engine/`** per ADR-033 MVP, not `stingar/webhook_listener.py`. |

See also: [CODE_REVIEW.md](./CODE_REVIEW.md) for module-level review of the hybrid implementation.
