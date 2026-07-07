#!/usr/bin/env bash
# Keep local STINGAR demo services alive; restarts anything that drops.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY="$ROOT/deploy/stingar"
PYTHON="$ROOT/.venv-demo/bin/python"
export ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://127.0.0.1:9200}"
export ELASTICSEARCH_HOST="${ELASTICSEARCH_HOST:-127.0.0.1}"
export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
export STINGAR_DATABASE_URL="sqlite:///$DEPLOY/storage/db/stingar.db"
export PYTHONPATH="$ROOT"

log() { echo "[keep-alive $(date +%H:%M:%S)] $*"; }

# shellcheck source=lib/clear-es-demo-blocks.sh
source "$ROOT/scripts/lib/clear-es-demo-blocks.sh"

ensure_es() {
  curl -fs --max-time 2 "$ELASTICSEARCH_URL" >/dev/null 2>&1 && return 0
  log "restarting Elasticsearch..."
  "$ROOT/scripts/start-elasticsearch-native.sh" >/dev/null 2>&1 || true
  clear_es_demo_blocks "$ELASTICSEARCH_URL"
}

ensure_lite() {
  curl -fs --max-time 2 http://127.0.0.1:8091/health >/dev/null 2>&1 && return 0
  log "restarting scanner-lite..."
  pkill -f "scanner_lite.server" 2>/dev/null || true
  nohup env ELASTICSEARCH_URL="$ELASTICSEARCH_URL" REDIS_URL="$REDIS_URL" \
    SCANNER_INVENTORY_BACKEND=redis STINGAR_STORAGE_BACKEND=elasticsearch \
    "$PYTHON" -m scanner_lite.server >>"$ROOT/.run/scanner-lite.log" 2>&1 &
}

ensure_api() {
  curl -fs --max-time 2 -H "API-KEY: local-demo-api-key" \
    "http://127.0.0.1:8000/api/v2/sessions?rows_per_page=1" >/dev/null 2>&1 && return 0
  log "restarting stingar-api..."
  pkill -f "gunicorn.*app:api" 2>/dev/null || true
  (
    cd "$ROOT/vendor/stingar-api"
    nohup env STINGAR_DATABASE_URL="$STINGAR_DATABASE_URL" ELASTICSEARCH_HOST="$ELASTICSEARCH_HOST" \
      "$ROOT/.venv-demo/bin/gunicorn" -b 127.0.0.1:8000 --timeout 120 app:api \
      >>"$ROOT/.run/stingar-api.log" 2>&1 &
  )
}

ensure_ui() {
  lsof -iTCP:3000 -sTCP:LISTEN >/dev/null 2>&1 && return 0
  log "restarting stingar-ui on :3000..."
  pkill -f "node start-server.js" 2>/dev/null || true
  (
    cd "$ROOT/vendor/stingar-ui"
    nohup env API_HOST=http://127.0.0.1:8000 API_KEY=local-demo-api-key \
      PASSPHRASE=local-demo-passphrase STINGAR_ENV_PATH="$DEPLOY/stingar.env" \
      NODE_ENV=development NEXT_PUBLIC_BYPASS_AUTH=true PORT=3000 HOSTNAME=0.0.0.0 \
      node start-server.js >>"$ROOT/.run/stingar-ui.log" 2>&1 &
    echo $! >"$ROOT/.run/stingar-ui.pid"
  )
  sleep 2
}

log "watchdog started — http://127.0.0.1:3000/dashboard/attack-analysis/overview"
while true; do
  ensure_es
  ensure_lite
  ensure_api
  ensure_ui
  sleep 15
done
