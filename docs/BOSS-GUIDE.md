# Stakeholder Guide — Scanner Enrichment Lite

**Audience:** technical lead / manager reviewing or demoing this work  
**Branch:** `scanner-enrichment-lite`  
**Author context:** Code+ / STINGAR enrichment sidecar for honeypot Attack Analysis

Use this doc to understand the system, run a demo yourself, run tests, and see how to wire it into real STINGAR source.

---

## 1. Elevator pitch (2 minutes)

STINGAR honeypots record every connection from the internet. Many of those source IPs are **known security scanners** (Censys, Shodan, Cortex Xpanse, Shadowserver, etc.). Reputation feeds often score them as “bad,” so analysts get false positives.

**Scanner Enrichment Lite** sits next to STINGAR and, for each source IP:

1. Checks a local known-scanner list first (free, fast)
2. If unknown, asks a short cascade of threat APIs (cost-capped)
3. Labels the session **benign / malicious / suspicious / unknown**
4. Writes that label into Elasticsearch next to the session
5. Shows it as an **OUTCOME** column in Attack Analysis

It does **not** replace STINGAR. It is a sidecar that enriches events before (or as) they land in the same Elasticsearch the UI already reads.

---

## 2. What problem this solves

| Before | After |
|---|---|
| Every probe looks like an “attack” | Known scanners marked **benign** |
| Analysts dig into Xpanse/Censys noise | OUTCOME column triage at a glance |
| No shared enrichment path into session docs | Enrichment lives on the session document the UI already queries |
| Paid API calls on every IP | Local inventory first; max 3 paid calls; early stop |

---

## 3. Mental model

```
Honeypot sensors
      │
      ▼
Fluentd (or webhook)
      │  HTTP POST
      ▼
scanner-lite  (:8091)  ← this project
      │  enrich + classify
      ▼
Elasticsearch  (stingar-* sessions + scanner-* indices)
      │
      ▼
stingar-ui Attack Analysis  →  OUTCOME column
```

**In scope on this branch:** `scanner_lite/`, deploy overlays, UI OUTCOME patch, ES templates, tests, demo scripts.

**Out of scope here (lives on `threat-enrich-agent`):** central sync server, sharing policy, Claude agent loop, full hybrid multi-node platform.

---

## 4. Outcomes explained simply

| OUTCOME | Meaning | Example |
|---|---|---|
| **benign** | Known scanner or clearly non-hostile probe noise | Cortex Xpanse `198.235.24.10` |
| **malicious** | Strong hostile signal from cascade / rules | Confirmed abuse / malicious intel |
| **suspicious** | Worth a look; not a clean scanner match | Unusual honeypot behavior tags (e.g. PeopleSoft + Go) |
| **unknown** | Not enough signal yet | New IP, APIs inconclusive |

Hover / drilldown also shows **investigation metadata**: behavior tags, frequency (how often today), priority, and which APIs were called (`api_call_trace`).

---

## 5. How to run a demo yourself

Pick **one** path. Prefer the lightest that matches your environment.

### Path A — API-only demo (laptop, ~10 minutes)

Best for “show me enrichment works” without a full STINGAR UI.

**Prereqs:** Python 3.10+, Elasticsearch on `:9200`, Redis on `:6379` (or use the native helper below).

```bash
git clone git@gitlab.oit.duke.edu:codeplus2026/ai_tools.git
# or: git clone git@github.com:Rudhmilaa/threat-intel-agent.git
cd ai_tools   # or threat-intel-agent
git checkout scanner-enrichment-lite

python -m venv .venv-demo
.venv-demo/bin/pip install -r requirements.txt

export ELASTICSEARCH_URL=http://127.0.0.1:9200
export STINGAR_STORAGE_BACKEND=elasticsearch
export REDIS_URL=redis://127.0.0.1:6379/0
export SCANNER_INVENTORY_BACKEND=redis

# If Docker disk is tight, native ES helper:
PYTHON=.venv-demo/bin/python ./scripts/deploy-scanner-lite.sh up-native
```

**Smoke ingest (known scanner → benign):**

```bash
curl -s -X POST http://127.0.0.1:8091/webhook/stingar \
  -H "Content-Type: application/json" \
  -d '{
    "srcIp": "198.235.24.10",
    "app": "web",
    "hpData": {"eventType": "service_probe"}
  }' | python3 -m json.tool
```

You should see `outcome_category: "benign"` and session index stats.

**Health check:**

```bash
curl -s http://127.0.0.1:8091/health | python3 -m json.tool
```

Full curl script with more IPs: [SCANNER-LITE-DEMO.md](./SCANNER-LITE-DEMO.md)

### Path B — Full local STINGAR + OUTCOME UI

Best for “show me the Attack Analysis column.”

```bash
./scripts/deploy-stingar-demo.sh
```

Needs Docker with ~10 GB free disk. Open Attack Analysis in the browser and hard-refresh (**Cmd+Shift+R**). Look for **OUTCOME** between Location and C2.

Details: [DEMO-DEPLOY.md](./DEMO-DEPLOY.md)

### Path C — Existing Duke STINGAR VM

Best when there is already a live URL (e.g. `https://vcm-XXXXX.vm.duke.edu/attack-analysis`).

Run deploy **on the VM**, not only on a laptop:

```bash
ssh <user>@vcm-XXXXX.vm.duke.edu
git clone … && cd … && git checkout scanner-enrichment-lite
export STINGAR_ROOT=/path/to/stingar/compose   # find with: find ~ -name docker-compose.yml
./scripts/deploy-stingar-duke-vm.sh
```

Then open the VM Attack Analysis URL and hard-refresh.

---

## 6. How to run tests yourself

```bash
python -m venv .venv-demo
.venv-demo/bin/pip install -r requirements.txt
.venv-demo/bin/python -m unittest discover -s tests -p 'test_*.py' -v
```

| Test area | What it proves |
|---|---|
| `test_classifier.py` | 4-category rules (scanners → benign, etc.) |
| `test_cascade.py` | Free local match first; paid call caps; early stop |
| `test_metadata.py` | Behavior / frequency / priority |
| `test_session_integration.py` | Session document mapping into STINGAR shape |
| `test_stingar_ingest.py` | Webhook / Fluentd payload parsing |
| `test_scanner_inventory.py` | CSV + feed inventory |

Reviewer checklist with manual verification: [CODE_REVIEW.md](./CODE_REVIEW.md)

---

## 7. How to integrate into STINGAR source / production

You do **not** need to rewrite STINGAR core for a first integration. Preferred pattern is a **sidecar + Fluentd redirect + optional UI patch**.

### 7.1 Sidecar on an existing compose stack (recommended)

1. Keep stock STINGAR images/services as-is.
2. Add scanner-lite via overlay:

```bash
export SCANNER_LITE_BUILD_CONTEXT=/path/to/this/repo

docker compose \
  -f docker-compose.yml \
  -f /path/to/this/repo/deploy/stingar/scanner-lite.overlay.yml \
  up -d scanner-lite fluentd
```

3. Replace Fluentd config so `stingar.events.*` POSTs to scanner-lite instead of writing sessions directly to ES:

- Source of truth: [`deploy/stingar/fluentd.conf`](../deploy/stingar/fluentd.conf)
- Concept: honeypot → Fluentd → **HTTP → scanner-lite:8091/ingest/fluentd** → Elasticsearch

4. Apply ES templates and seed scanner inventory:

```bash
./scripts/deploy-stingar-integration.sh templates
./scripts/deploy-stingar-integration.sh seed-redis
./scripts/deploy-stingar-integration.sh smoke
```

Reference: [STINGAR-INTEGRATION.md](./STINGAR-INTEGRATION.md) · [deploy/stingar/README.md](../deploy/stingar/README.md)

### 7.2 What lands on each session document

After enrichment, session docs include fields the UI can read, including:

- `outcome_category` — primary Attack Analysis column
- `outcome_summary` — compact hover / drilldown text
- `investigation.*` — richer analyst context
- `hp_data.enrichment.scanner_lite.*` — full scanner-lite payload

UI field notes: [STINGAR-UI-OUTCOME-COLUMN.md](./STINGAR-UI-OUTCOME-COLUMN.md)

### 7.3 UI (OUTCOME column)

Patched Attack Analysis lives under [`vendor/stingar-ui/`](../vendor/stingar-ui/). Production options:

| Approach | When to use |
|---|---|
| Build UI from `vendor/stingar-ui` in compose | Demo / controlled deploy |
| Port the OUTCOME column patch into upstream STINGAR UI source | Long-term productization |
| Keep stock UI; use Kibana dashboards | No UI rebuild available |

Kibana import (API/demo path):

```bash
export KIBANA_URL=http://127.0.0.1:5601
./scripts/import-scanner-lite-dashboards.sh
# or for full STINGAR stack:
./scripts/import-stingar-dashboards.sh
```

### 7.4 Refreshing vendored STINGAR trees

```bash
./scripts/extract-stingar-images.sh
```

Re-apply UI patches after re-extract (OUTCOME column helpers).

### 7.5 Integration checklist for production owners

- [ ] Network: Fluentd can reach `scanner-lite:8091`; only internal networks hit `/ingest/fluentd`
- [ ] Redis (or file backend) seeded with scanner inventory
- [ ] ES templates applied (`scanner-*`, stingar enriched mappings)
- [ ] Optional API keys for cascade (`ABUSEIPDB_API_KEY`, etc.) — works without keys, with reduced paid coverage
- [ ] Optional `STINGAR_WEBHOOK_SECRET` if using webhook ingest
- [ ] UI rebuild or Kibana dashboard for visibility
- [ ] Smoke: known scanner IP → `benign`; unknown IP → cascade trace present

---

## 8. Key files to skim before a review meeting

| Order | File | Why |
|---|---|---|
| 1 | `scanner_lite/enrich.py` | Orchestration + dual-write |
| 2 | `scanner_lite/cascade.py` | Cost model / API order |
| 3 | `scanner_lite/classifier.py` | Outcome rules |
| 4 | `scanner_lite/session_document.py` | STINGAR field mapping |
| 5 | `scanner_lite/server.py` | HTTP API surface |
| 6 | `deploy/stingar/fluentd.conf` | How events leave Fluentd |
| 7 | `deploy/stingar/scanner-lite.overlay.yml` | Drop-in compose |

Architecture diagrams: [SCANNER-LITE-ARCHITECTURE.md](./SCANNER-LITE-ARCHITECTURE.md)

---

## 9. Demo talking points (meeting script)

1. **Problem:** honeypots are flooded with scanner noise that looks malicious on raw reputation.
2. **Approach:** free local inventory first; paid APIs only when needed; hard cap on spend.
3. **Output:** four clear OUTCOMEs on the same session docs STINGAR already uses.
4. **Live proof:** ingest `198.235.24.10` → benign; show OUTCOME in UI or curl JSON.
5. **Integration:** sidecar + Fluentd HTTP, not a fork of STINGAR core.
6. **Next steps:** production API keys, inventory refresh cadence, upstream UI merge if desired.

---

## 10. Repos and branches

| Location | Remote |
|---|---|
| Duke GitLab | `git@gitlab.oit.duke.edu:codeplus2026/ai_tools.git` → branch `scanner-enrichment-lite` |
| Private GitHub | `git@github.com:Rudhmilaa/threat-intel-agent.git` → branch `scanner-enrichment-lite` |

Related branch (full platform reference): `threat-enrich-agent`.

---

## 11. Need help?

| Question | Doc |
|---|---|
| One-command deploy / Duke VM | [DEMO-DEPLOY.md](./DEMO-DEPLOY.md) |
| Curl-by-curl demo | [SCANNER-LITE-DEMO.md](./SCANNER-LITE-DEMO.md) |
| Cascade cost / ranking | [API-CASCADE.md](./API-CASCADE.md) |
| Reviewer verification | [CODE_REVIEW.md](./CODE_REVIEW.md) |
| Project README | [../README.md](../README.md) |
