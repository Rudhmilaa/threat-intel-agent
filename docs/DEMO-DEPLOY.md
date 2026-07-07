# STINGAR + Scanner-Lite Demo Deploy Guide

Deploy the **OUTCOME** column demo for collaborators on branch **`scanner-enrichment-lite`**.

> **Disk space:** The full Docker demo (STINGAR UI build + images) needs **≥10 GB free**. If `docker compose build` fails with `input/output error`, free disk first, then run `./scripts/deploy-stingar-demo.sh` again. For a **lighter API-only demo** without the patched UI: `./scripts/deploy-scanner-lite.sh up-native`.

## What you get

- Patched **stingar-ui** (Attack Analysis shows `outcome_category` badges + hover metadata)
- **scanner-lite** enrichment sidecar (fluentd → HTTP ingest → Elasticsearch)
- **Redis** scanner inventory cache
- Sample ingest events for a live demo

## Requirements

| Item | Detail |
|------|--------|
| Branch | `scanner-enrichment-lite` |
| Docker Desktop | Running, **≥10 GB free disk** (first UI build needs several GB) |
| OS | macOS or Linux with Docker; demo commands use `localhost` |
| Network | Pull `4warned/*:v2.3` images from Docker Hub |
| Python 3 | For Redis seed (script creates `.venv-demo` if needed) |

**Important:** Run deploy on the **same machine** you open in the browser. Building on a laptop while viewing a remote VM URL will **not** update the VM.

## Quick start (one command)

```bash
git clone git@gitlab.oit.duke.edu:codeplus2026/ai_tools.git
cd ai_tools
git checkout scanner-enrichment-lite

./scripts/deploy-stingar-demo.sh
```

Then open **https://localhost/** (accept the self-signed certificate), go to **Attack Analysis → Overview**, and hard-refresh (**Cmd+Shift+R** / **Ctrl+Shift+R**).

## Step-by-step (manual)

### 1. Clone and checkout

```bash
git clone git@gitlab.oit.duke.edu:codeplus2026/ai_tools.git
cd ai_tools
git checkout scanner-enrichment-lite
```

`vendor/stingar-ui` is committed on this branch — no image extract step required for the UI demo.

### 2. Check disk and Docker

```bash
df -h /
docker info
```

If Docker fails or disk is ~100% full:

- Empty Trash, remove large caches
- Restart Docker Desktop
- Optional: `docker system prune -a` (removes unused images)

### 3. Create config

```bash
cd deploy/stingar
mkdir -p storage/db certs
cp stingar.env.demo stingar.env
```

Or from repo root: `./scripts/deploy-stingar-ui-vm.sh` creates `stingar.env` and TLS certs automatically.

### 4. Start the stack

```bash
cd deploy/stingar
docker compose up -d --build
```

Wait for Elasticsearch (1–5 minutes first time):

```bash
curl -s http://127.0.0.1:9200/_cluster/health?pretty
```

### 5. Bootstrap templates, Redis, smoke test

From **repo root**:

```bash
python3 -m venv .venv-demo
source .venv-demo/bin/activate   # Windows: .venv-demo\Scripts\activate
pip install -r requirements.txt

./scripts/deploy-stingar-integration.sh templates
./scripts/deploy-stingar-integration.sh seed-redis
./scripts/deploy-stingar-integration.sh smoke
```

### 6. Rebuild UI only (after code changes)

```bash
./scripts/deploy-stingar-ui-vm.sh
```

### 7. Demo ingest (optional extra events)

```bash
# Known scanner → benign
curl -X POST http://127.0.0.1:8091/ingest/fluentd \
  -H "Content-Type: application/json" \
  -d '{"srcIp":"198.235.24.10","app":"web","hpData":{"eventType":"service_probe"}}'

# PeopleSoft-style probe → suspicious
curl -X POST http://127.0.0.1:8091/ingest/fluentd \
  -H "Content-Type: application/json" \
  -d '{"app":"peoplesoft","srcIp":"52.29.178.95","hpData":{"method":"HEAD","path":"/ps/signon.html","eventType":"peoplesoft-scan"}}'
```

Or: `./scripts/deploy-stingar-demo.sh ingest`

## URLs

| Service | URL |
|---------|-----|
| STINGAR UI (nginx) | https://localhost/ |
| STINGAR UI direct | http://127.0.0.1:3000/ |
| Kibana | http://127.0.0.1:5601/ |
| Elasticsearch | http://127.0.0.1:9200/ |
| scanner-lite API | http://127.0.0.1:8091/health |

## Verification

```bash
# scanner-lite + Redis inventory
curl -s http://127.0.0.1:8091/health | python3 -m json.tool

# Latest enriched sessions
curl -s "http://127.0.0.1:9200/stingar-*/_search" \
  -H "Content-Type: application/json" \
  -d '{"size":3,"sort":[{"@timestamp":"desc"}],"_source":["src_ip","outcome_category","outcome_summary"]}' \
  | python3 -m json.tool

# Container status
cd deploy/stingar && docker compose ps
```

Expected UI: **OUTCOME** column between Location and C2; hover shows scanner vendor, CIDR, priority, reasons.

## Existing STINGAR VM (overlay)

If stock STINGAR already runs elsewhere on the VM:

```bash
git clone ... && cd ai_tools && git checkout scanner-enrichment-lite

# From your existing STINGAR directory:
cp /path/to/ai_tools/deploy/stingar/fluentd.conf ./fluentd.conf
export SCANNER_LITE_BUILD_CONTEXT=/path/to/ai_tools
docker compose \
  -f docker-compose.yml \
  -f /path/to/ai_tools/deploy/stingar/scanner-lite.overlay.yml \
  up -d --build scanner-lite fluentd

cd /path/to/ai_tools
./scripts/deploy-stingar-integration.sh templates
./scripts/deploy-stingar-integration.sh seed-redis
STINGAR_DEPLOY_DIR=/path/to/existing/stingar ./scripts/deploy-stingar-ui-vm.sh
```

Open the **VM hostname** in the browser, not `localhost` on your laptop.

## Lightweight demo (no full STINGAR UI)

API + Kibana only:

```bash
./scripts/deploy-scanner-lite.sh up
```

See [SCANNER-LITE-DEMO.md](./SCANNER-LITE-DEMO.md).

## Troubleshooting

| Problem | Cause | Fix |
|---------|--------|-----|
| `stingar.env not found` | Config missing | `cp deploy/stingar/stingar.env.demo deploy/stingar/stingar.env` |
| Build fails at `npm install` | Disk full | Free ≥10 GB, restart Docker, retry |
| UI unchanged | `compose up` never ran | `cd deploy/stingar && docker compose up -d stingarui web` |
| VM UI unchanged | Built on wrong host | Deploy on the VM |
| OUTCOME empty | No enriched sessions | Run `seed-redis`, `smoke`, demo curl ingest |
| All `unknown` | Redis empty | `./scripts/deploy-stingar-integration.sh seed-redis` |
| Docker 500 / EOF | Daemon crashed | Quit Docker, free disk, reopen |

## Scripts reference

| Script | Purpose |
|--------|---------|
| `./scripts/deploy-stingar-demo.sh` | Full local demo (compose + bootstrap + sample events) |
| `./scripts/deploy-stingar-ui-vm.sh` | Rebuild patched UI + core services |
| `./scripts/deploy-stingar-integration.sh` | Templates, Redis seed, smoke ingest |
| `./scripts/deploy-scanner-lite.sh` | Lighter stack without full STINGAR UI |

## Related docs

- [STINGAR-INTEGRATION.md](./STINGAR-INTEGRATION.md) — architecture
- [STINGAR-UI-OUTCOME-COLUMN.md](./STINGAR-UI-OUTCOME-COLUMN.md) — UI fields
- [deploy/stingar/README.md](../deploy/stingar/README.md) — compose layout
