#!/usr/bin/env bash
# Scanner enrichment lite: Elasticsearch + templates + API server + demo
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-$ROOT/.venv-demo/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="${PYTHON:-python3}"
fi

ensure_venv() {
  if [[ -x "$ROOT/.venv-demo/bin/python" ]]; then
    PYTHON="$ROOT/.venv-demo/bin/python"
    return 0
  fi
  log "Creating .venv-demo and installing requirements..."
  python3 -m venv "$ROOT/.venv-demo"
  "$ROOT/.venv-demo/bin/pip" install -q -r "$ROOT/requirements.txt"
  PYTHON="$ROOT/.venv-demo/bin/python"
}

export STINGAR_ES_URL="${STINGAR_ES_URL:-http://127.0.0.1:9200}"
export ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-$STINGAR_ES_URL}"
export STINGAR_STORAGE_BACKEND=elasticsearch
export SCANNER_LITE_PORT="${SCANNER_LITE_PORT:-8091}"
export KIBANA_URL="${KIBANA_URL:-http://127.0.0.1:5601}"
export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
export SCANNER_INVENTORY_BACKEND="${SCANNER_INVENTORY_BACKEND:-redis}"

log() { echo "[deploy-scanner-lite] $*"; }

check_disk_space() {
  local avail_kb
  avail_kb=$(df -k /System/Volumes/Data 2>/dev/null | awk 'NR==2 {print $4}')
  if [[ -n "$avail_kb" && "$avail_kb" -lt 3145728 ]]; then
    log "WARNING: Low disk space ($(df -h /System/Volumes/Data | awk 'NR==2 {print $4}') free)."
    log "Docker Desktop often fails with FILE_ERROR_NO_SPACE when the disk is full."
    log "Free space (Trash, large caches) or use: $0 up-native"
    return 1
  fi
  return 0
}

docker_ready() {
  docker info >/dev/null 2>&1
}

ensure_docker() {
  if docker_ready; then
    return 0
  fi
  check_disk_space || true
  log "Starting Docker..."
  open -a "/Applications/Docker.app/Contents/MacOS/Docker Desktop.app" 2>/dev/null \
    || open -a Docker 2>/dev/null || true
  for i in $(seq 1 30); do
    if docker_ready; then
      log "Docker ready after ${i}s"
      return 0
    fi
    sleep 2
  done
  echo "Docker not running. If the GUI won't open, check disk space (need several GB free)." >&2
  echo "Alternative: $0 up-native  (Homebrew Elasticsearch, no Docker)" >&2
  exit 1
}

start_es_docker() {
  ensure_docker
  log "Starting Elasticsearch + Kibana + Redis (Docker)..."
  docker compose -f deploy/docker-compose.yml up -d elasticsearch kibana redis
  wait_for_redis
  wait_for_es
}

start_es_native() {
  log "Starting Elasticsearch without Docker..."
  "$ROOT/scripts/start-elasticsearch-native.sh"
  wait_for_es
}

wait_for_es() {
  for _ in $(seq 1 60); do
    curl -fs "$STINGAR_ES_URL" >/dev/null 2>&1 && break
    sleep 2
  done
  curl -fs "$STINGAR_ES_URL" >/dev/null 2>&1 || { echo "ES not ready at $STINGAR_ES_URL" >&2; exit 1; }
  log "Elasticsearch is up at $STINGAR_ES_URL"
}

wait_for_redis() {
  for _ in $(seq 1 30); do
    if "$PYTHON" - <<'PY' >/dev/null 2>&1; then
import os
import redis
redis.from_url(os.environ["REDIS_URL"]).ping()
PY
      log "Redis is up at $REDIS_URL"
      return 0
    fi
    sleep 1
  done
  log "WARNING: Redis not ready at $REDIS_URL — seed and scanner cache may fail"
}

seed_scanner_redis_if_needed() {
  if "$PYTHON" - <<'PY' >/dev/null 2>&1; then
import os
from threat_intel.scanner_redis_store import get_scanner_redis_store
store = get_scanner_redis_store()
raise SystemExit(0 if store.is_populated() else 1)
PY
    log "Scanner Redis inventory already populated"
    return 0
  fi
  log "Seeding scanner inventory (files → Redis → ES)..."
  "$PYTHON" "$ROOT/scripts/seed-scanner-redis.py" || log "Redis seed failed (non-fatal if using file backend)"
}

start_es() {
  start_es_docker
}

start_kibana() {
  for _ in $(seq 1 60); do
    curl -fs "$KIBANA_URL/api/status" >/dev/null 2>&1 && break
    sleep 3
  done
  if curl -fs "$KIBANA_URL/api/status" >/dev/null 2>&1; then
    log "Kibana is up at $KIBANA_URL"
  else
    log "Kibana not ready — skip dashboard import (start with: docker compose -f deploy/docker-compose.yml up -d kibana)"
  fi
}

import_dashboards() {
  if curl -fs "$KIBANA_URL/api/status" >/dev/null 2>&1; then
    log "Importing scanner-lite Kibana dashboards..."
    "$ROOT/scripts/import-scanner-lite-dashboards.sh" || log "Dashboard import failed (non-fatal)"
  fi
}

apply_templates() {
  log "Applying scanner-lite index templates..."
  curl -fsS -X PUT "$STINGAR_ES_URL/_index_template/scanner-ip-enrichment" \
    -H "Content-Type: application/json" \
    -d @"$ROOT/es/templates/scanner-ip-enrichment.json" >/dev/null
  curl -fsS -X PUT "$STINGAR_ES_URL/_index_template/scanner-asn-batches" \
    -H "Content-Type: application/json" \
    -d @"$ROOT/es/templates/scanner-asn-batches.json" >/dev/null
  curl -fsS -X PUT "$STINGAR_ES_URL/_index_template/stingar-enriched" \
    -H "Content-Type: application/json" \
    -d @"$ROOT/es/templates/stingar-enriched.json" >/dev/null
  curl -fsS -X PUT "$STINGAR_ES_URL/_index_template/scanner-inventory" \
    -H "Content-Type: application/json" \
    -d @"$ROOT/es/templates/scanner-inventory.json" >/dev/null
  log "Templates applied"
}

start_server() {
  mkdir -p "$ROOT/.run"
  if [[ -f "$ROOT/.run/scanner-lite.pid" ]] && kill -0 "$(cat "$ROOT/.run/scanner-lite.pid")" 2>/dev/null; then
    if curl -fs "http://127.0.0.1:$SCANNER_LITE_PORT/health" >/dev/null 2>&1; then
      log "scanner-lite already running (PID $(cat "$ROOT/.run/scanner-lite.pid"))"
      return 0
    fi
  fi
  log "Starting scanner-lite API on :$SCANNER_LITE_PORT ..."
  nohup env ELASTICSEARCH_URL="$ELASTICSEARCH_URL" \
    REDIS_URL="${REDIS_URL:-}" \
    SCANNER_INVENTORY_BACKEND="${SCANNER_INVENTORY_BACKEND:-file}" \
    STINGAR_STORAGE_BACKEND=elasticsearch \
    SCANNER_LITE_HOST=127.0.0.1 \
    SCANNER_LITE_PORT="$SCANNER_LITE_PORT" \
    "$PYTHON" -m scanner_lite.server >>"$ROOT/.run/scanner-lite.log" 2>&1 &
  echo $! >"$ROOT/.run/scanner-lite.pid"
  disown 2>/dev/null || true
  for _ in $(seq 1 30); do
    curl -fs "http://127.0.0.1:$SCANNER_LITE_PORT/health" >/dev/null 2>&1 && break
    sleep 1
  done
  log "Server PID $(cat "$ROOT/.run/scanner-lite.pid")"
}

demo_events() {
  log "Sending demo events..."
  curl -fsS -X POST "http://127.0.0.1:$SCANNER_LITE_PORT/scanner-lite/enrich/events" \
    -H "Content-Type: application/json" \
    -d '{
      "events": [
        {
          "source_ip": "203.0.113.42",
          "destination_ip": "10.0.0.25",
          "destination_port": 22,
          "attack_type": "ssh_bruteforce",
          "protocol": "ssh",
          "honeypot_type": "cowrie"
        },
        {
          "source_ip": "198.235.24.10",
          "destination_ip": "10.0.0.25",
          "destination_port": 8080,
          "attack_type": "service_probe",
          "protocol": "http",
          "honeypot_type": "web"
        }
      ]
    }' | "$PYTHON" -m json.tool

  echo
  log "STINGAR webhook demo (PeopleSoft probe)..."
  curl -fsS -X POST "http://127.0.0.1:$SCANNER_LITE_PORT/webhook/stingar" \
    -H "Content-Type: application/json" \
    -d '{
      "events": [
        {
          "app": "peoplesoft",
          "srcIp": "52.29.178.95",
          "dstIp": "150.136.255.191",
          "dstPort": 8000,
          "hpData": {
            "method": "HEAD",
            "path": "/ps/signon.html",
            "eventType": "peoplesoft-scan",
            "headers": {"UserAgent": "Go-http-client/1.1"}
          }
        }
      ]
    }' | "$PYTHON" -m json.tool

  echo
  log "ASN batches:"
  curl -fsS "http://127.0.0.1:$SCANNER_LITE_PORT/scanner-lite/batches/asn" | "$PYTHON" -m json.tool
}

case "${1:-up}" in
  up)
    ensure_venv
    start_es
    apply_templates
    seed_scanner_redis_if_needed
    start_kibana
    start_server
    demo_events
    import_dashboards
    log "Kibana: $KIBANA_URL/app/dashboards#/view/scanner-lite-dashboard"
    log "Inventory meta: curl http://127.0.0.1:$SCANNER_LITE_PORT/scanner-lite/inventory/meta"
    log "Logs: .run/scanner-lite.log"
    ;;
  up-native)
    ensure_venv
    start_es_native
    apply_templates
    seed_scanner_redis_if_needed
    start_server
    demo_events
    log "Elasticsearch (native Homebrew). Kibana skipped — use curl/API demo or free disk for Docker."
    log "Session search: curl 'http://127.0.0.1:$SCANNER_LITE_PORT/scanner-lite/sessions?q=outcome:suspicious&hours=24'"
    log "Inventory meta: curl http://127.0.0.1:$SCANNER_LITE_PORT/scanner-lite/inventory/meta"
    log "Logs: .run/scanner-lite.log"
    ;;
  es-only)
    start_es
    apply_templates
    seed_scanner_redis_if_needed
    ;;
  es-native)
    start_es_native
    apply_templates
    seed_scanner_redis_if_needed
    ;;
  dashboards)
    import_dashboards
    ;;
  *)
    echo "Usage: $0 [up|up-native|es-only|es-native|dashboards]" >&2
    echo "  up-native  Elasticsearch via Homebrew (no Docker) — use when Docker won't start" >&2
    exit 1
    ;;
esac
