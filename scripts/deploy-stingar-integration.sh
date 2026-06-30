#!/usr/bin/env bash
# Wire scanner-lite into a STINGAR v2.3 docker-compose stack.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-$ROOT/.venv-demo/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="${PYTHON:-python3}"
fi

export ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://127.0.0.1:9200}"
export KIBANA_URL="${KIBANA_URL:-http://127.0.0.1:5601}"
export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
export SCANNER_INVENTORY_BACKEND="${SCANNER_INVENTORY_BACKEND:-redis}"
export STINGAR_STORAGE_BACKEND=elasticsearch
export SCANNER_LITE_PORT="${SCANNER_LITE_PORT:-8091}"
export SCANNER_LITE_URL="${SCANNER_LITE_URL:-http://127.0.0.1:$SCANNER_LITE_PORT}"

log() { echo "[deploy-stingar-integration] $*"; }

apply_templates() {
  log "Applying Elasticsearch index templates..."
  curl -fsS -X PUT "$ELASTICSEARCH_URL/_index_template/stingar-enriched" \
    -H "Content-Type: application/json" \
    -d @"$ROOT/es/templates/stingar-enriched.json" >/dev/null
  curl -fsS -X PUT "$ELASTICSEARCH_URL/_index_template/scanner-ip-enrichment" \
    -H "Content-Type: application/json" \
    -d @"$ROOT/es/templates/scanner-ip-enrichment.json" >/dev/null
  curl -fsS -X PUT "$ELASTICSEARCH_URL/_index_template/scanner-inventory" \
    -H "Content-Type: application/json" \
    -d @"$ROOT/es/templates/scanner-inventory.json" >/dev/null
  log "Templates applied"
}

seed_redis_if_needed() {
  if ! redis-cli -u "$REDIS_URL" ping >/dev/null 2>&1; then
    log "Redis not reachable — skipping seed"
    return 0
  fi
  if "$PYTHON" - <<'PY' >/dev/null 2>&1; then
import os
from threat_intel.scanner_redis_store import get_scanner_redis_store
raise SystemExit(0 if get_scanner_redis_store().is_populated() else 1)
PY
    log "Scanner Redis inventory already populated"
    return 0
  fi
  log "Seeding scanner inventory into Redis..."
  "$PYTHON" "$ROOT/scripts/seed-scanner-redis.py" --skip-es || log "Redis seed failed (non-fatal)"
}

start_scanner_lite() {
  mkdir -p "$ROOT/.run"
  if curl -fs "$SCANNER_LITE_URL/health" >/dev/null 2>&1; then
    log "scanner-lite already running on $SCANNER_LITE_URL"
    return 0
  fi
  log "Starting scanner-lite on $SCANNER_LITE_URL ..."
  env ELASTICSEARCH_URL="$ELASTICSEARCH_URL" \
    REDIS_URL="$REDIS_URL" \
    SCANNER_INVENTORY_BACKEND="$SCANNER_INVENTORY_BACKEND" \
    STINGAR_STORAGE_BACKEND=elasticsearch \
    SCANNER_LITE_HOST=127.0.0.1 \
    SCANNER_LITE_PORT="$SCANNER_LITE_PORT" \
    "$PYTHON" -m scanner_lite.server >"$ROOT/.run/scanner-lite.log" 2>&1 &
  echo $! >"$ROOT/.run/scanner-lite.pid"
  for _ in $(seq 1 30); do
    curl -fs "$SCANNER_LITE_URL/health" >/dev/null 2>&1 && break
    sleep 1
  done
  log "scanner-lite PID $(cat "$ROOT/.run/scanner-lite.pid")"
}

smoke_test_ingest() {
  if ! curl -fs "$SCANNER_LITE_URL/health" >/dev/null 2>&1; then
    log "scanner-lite not reachable at $SCANNER_LITE_URL — skip smoke test"
    return 0
  fi
  log "Fluentd ingest smoke test..."
  local payload='{"app":"peoplesoft","srcIp":"52.29.178.95","hpData":{"method":"HEAD","path":"/ps/signon.html","eventType":"peoplesoft-scan"}}'
  curl -fsS -X POST "$SCANNER_LITE_URL/ingest/fluentd" \
    -H "Content-Type: application/json" \
    -d "$payload" >/dev/null \
    && log "Ingest accepted" \
    || log "Ingest failed (non-fatal if ES down)"
}

compose_up() {
  local compose_dir="$ROOT/deploy/stingar"
  if ! command -v docker >/dev/null 2>&1; then
    log "docker not installed — skip compose up"
    return 0
  fi
  if ! docker info >/dev/null 2>&1; then
    log "Docker daemon not running — skip compose up"
    return 0
  fi
  log "Starting STINGAR + scanner-lite via docker compose..."
  (cd "$compose_dir" && docker compose up -d --build scanner-lite)
}

case "${1:-up}" in
  templates)
    apply_templates
    ;;
  seed-redis)
    seed_redis_if_needed
    ;;
  smoke)
    smoke_test_ingest
    ;;
  compose)
    compose_up
    ;;
  up)
    apply_templates
    seed_redis_if_needed
    if curl -fs "$ELASTICSEARCH_URL" >/dev/null 2>&1; then
      :
    else
      log "Elasticsearch not reachable at $ELASTICSEARCH_URL"
    fi
    if curl -fs "$SCANNER_LITE_URL/health" >/dev/null 2>&1; then
      log "Using existing scanner-lite container/process"
    else
      start_scanner_lite
    fi
    smoke_test_ingest
    if curl -fs "$KIBANA_URL/api/status" >/dev/null 2>&1; then
      "$ROOT/scripts/import-stingar-dashboards.sh" || log "Kibana import failed (non-fatal)"
    fi
    log "Health: curl $SCANNER_LITE_URL/health"
    log "Full stack: cd deploy/stingar && docker compose up -d"
    log "Overlay: docker compose -f <stingar-compose.yml> -f deploy/stingar/scanner-lite.overlay.yml up -d"
    ;;
  dashboards)
    "$ROOT/scripts/import-stingar-dashboards.sh"
    ;;
  *)
    echo "Usage: $0 [up|templates|seed-redis|smoke|compose|dashboards]" >&2
    exit 1
    ;;
esac
