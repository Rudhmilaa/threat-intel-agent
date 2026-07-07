#!/usr/bin/env bash
# Local STINGAR UI demo (no Docker build): native ES + scanner-lite + stingar-api + patched UI.
# Needs ~2GB free disk. On the STINGAR VM with Docker, use ./scripts/deploy-stingar-ui-vm.sh instead.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY="$ROOT/deploy/stingar"
PYTHON="${PYTHON:-$ROOT/.venv-demo/bin/python}"
PIP="${PIP:-$ROOT/.venv-demo/bin/pip}"
mkdir -p "$ROOT/.run" "$DEPLOY/storage/db"

export ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://127.0.0.1:9200}"
export ELASTICSEARCH_HOST="${ELASTICSEARCH_HOST:-127.0.0.1}"
export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
export SCANNER_INVENTORY_BACKEND="${SCANNER_INVENTORY_BACKEND:-redis}"
export STINGAR_STORAGE_BACKEND=elasticsearch
export STINGAR_DATABASE_URL="sqlite:///$DEPLOY/storage/db/stingar.db"
export PYTHONPATH="$ROOT"

log() { echo "[demo-stingar-ui] $*"; }

# shellcheck source=lib/clear-es-demo-blocks.sh
source "$ROOT/scripts/lib/clear-es-demo-blocks.sh"

avail_kb=$(df -k /System/Volumes/Data 2>/dev/null | awk 'NR==2 {print $4}')
if [[ -n "$avail_kb" && "$avail_kb" -lt 2097152 ]]; then
  log "WARNING: less than 2GB free — free disk space first or use the STINGAR VM."
fi

cp -f "$DEPLOY/stingar.env.demo" "$DEPLOY/stingar.env"

if ! curl -fs "$ELASTICSEARCH_URL" >/dev/null 2>&1; then
  "$ROOT/scripts/start-elasticsearch-native.sh"
fi
clear_es_demo_blocks "$ELASTICSEARCH_URL"

redis-cli ping >/dev/null 2>&1 || brew services start redis >/dev/null 2>&1 || redis-server --daemonize yes

"$PIP" install -q sqlalchemy falcon falcon-swagger-ui 'elasticsearch>=7,<8' elasticsearch-dsl \
  gunicorn cryptography paramiko docker requests pyyaml jinja2 python-dateutil httpx 2>/dev/null || true

for t in stingar-enriched scanner-ip-enrichment scanner-inventory scanner-asn-batches; do
  curl -fsS -X PUT "$ELASTICSEARCH_URL/_index_template/$t" \
    -H "Content-Type: application/json" \
    -d @"$ROOT/es/templates/$t.json" >/dev/null
done
curl -fsS -X DELETE "$ELASTICSEARCH_URL/stingar-$(date +%Y-%m-%d)" >/dev/null 2>&1 || true

"$PYTHON" "$ROOT/scripts/seed-scanner-redis.py" --skip-es >/dev/null 2>&1 || true

"$PYTHON" <<'PY'
import os, sys
sys.path.insert(0, "vendor/stingar-api")
from storage.db import StingarDB
db = StingarDB(os.environ["STINGAR_DATABASE_URL"])
if not db.check_token("local-demo-api-key"):
    db.create_user(username="demo", password="demo", email="demo@local", token="local-demo-api-key")
PY

pkill -f "scanner_lite.server" 2>/dev/null || true
nohup env ELASTICSEARCH_URL="$ELASTICSEARCH_URL" REDIS_URL="$REDIS_URL" \
  SCANNER_INVENTORY_BACKEND="$SCANNER_INVENTORY_BACKEND" STINGAR_STORAGE_BACKEND=elasticsearch \
  "$PYTHON" -m scanner_lite.server >>"$ROOT/.run/scanner-lite.log" 2>&1 &
echo $! >"$ROOT/.run/scanner-lite.pid"

for _ in $(seq 1 25); do curl -fs http://127.0.0.1:8091/health >/dev/null 2>&1 && break; sleep 1; done

for payload in \
  '{"app":"web","srcIp":"198.235.24.10","hpData":{"eventType":"service_probe"}}' \
  '{"app":"peoplesoft","srcIp":"52.29.178.95","hpData":{"method":"HEAD","path":"/ps/signon.html","eventType":"peoplesoft-scan"}}' \
  '{"app":"ssh","srcIp":"203.0.113.42","hpData":{"eventType":"bruteforce"}}'; do
  curl -fsS -X POST http://127.0.0.1:8091/ingest/fluentd \
    -H "Content-Type: application/json" -d "$payload" >/dev/null
done

pkill -f "gunicorn.*app:api" 2>/dev/null || true
(
  cd "$ROOT/vendor/stingar-api"
  nohup env STINGAR_DATABASE_URL="$STINGAR_DATABASE_URL" ELASTICSEARCH_HOST="$ELASTICSEARCH_HOST" \
    "$ROOT/.venv-demo/bin/gunicorn" -b 127.0.0.1:8000 --timeout 120 app:api \
    >>"$ROOT/.run/stingar-api.log" 2>&1 &
  echo $! >"$ROOT/.run/stingar-api.pid"
)

pkill -f "node start-server.js" 2>/dev/null || true
pkill -f "npm start" 2>/dev/null || true
(
  cd "$ROOT/vendor/stingar-ui"
  nohup env API_HOST=http://127.0.0.1:8000 API_KEY=local-demo-api-key \
    PASSPHRASE=local-demo-passphrase STINGAR_ENV_PATH="$DEPLOY/stingar.env" \
    NODE_ENV=development NEXT_PUBLIC_BYPASS_AUTH=true PORT=3000 HOSTNAME=0.0.0.0 \
    node start-server.js >>"$ROOT/.run/stingar-ui.log" 2>&1 &
  echo $! >"$ROOT/.run/stingar-ui.pid"
)

for _ in $(seq 1 30); do
  curl -fs -H "API-KEY: local-demo-api-key" \
    "http://127.0.0.1:8000/api/v2/sessions?rows_per_page=1" >/dev/null 2>&1 && break
  sleep 1
done

count=$(curl -fs -H "API-KEY: local-demo-api-key" \
  "http://127.0.0.1:8000/api/v2/sessions?rows_per_page=20" \
  | "$PYTHON" -c "import json,sys; print(json.load(sys.stdin)['data']['count'])")

log "Ready — $count session rows in API"
log "Open: http://127.0.0.1:3000/dashboard/attack-analysis/overview"
log "OUTCOME column is between Location and C2; hover for scanner metadata."
log "API key: local-demo-api-key  |  logs: .run/stingar-*.log"

if ! pgrep -f "keep-stingar-demo-alive.sh" >/dev/null 2>&1; then
  nohup "$ROOT/scripts/keep-stingar-demo-alive.sh" >>"$ROOT/.run/keep-alive.log" 2>&1 &
  log "Started keep-alive watchdog (./scripts/demo-stop.sh to tear down)"
fi

if [[ "$(uname -s)" == "Darwin" ]]; then
  open "http://127.0.0.1:3000/dashboard/attack-analysis/overview" 2>/dev/null || true
fi
