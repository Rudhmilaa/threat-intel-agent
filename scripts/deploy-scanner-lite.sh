#!/usr/bin/env bash
# Scanner enrichment lite: Elasticsearch + templates + API server + demo
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-$ROOT/.venv-1/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="${PYTHON:-python3}"
fi

export STINGAR_ES_URL="${STINGAR_ES_URL:-http://127.0.0.1:9200}"
export ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-$STINGAR_ES_URL}"
export STINGAR_STORAGE_BACKEND=elasticsearch
export SCANNER_LITE_PORT="${SCANNER_LITE_PORT:-8091}"

log() { echo "[deploy-scanner-lite] $*"; }

ensure_docker() {
  if ! docker info >/dev/null 2>&1; then
    log "Starting Docker..."
    open -a Docker 2>/dev/null || true
    for _ in $(seq 1 30); do
      docker info >/dev/null 2>&1 && break
      sleep 2
    done
  fi
  docker info >/dev/null 2>&1 || { echo "Docker not running" >&2; exit 1; }
}

start_es() {
  ensure_docker
  log "Starting Elasticsearch..."
  docker compose -f deploy/docker-compose.yml up -d elasticsearch
  for _ in $(seq 1 60); do
    curl -fs "$STINGAR_ES_URL" >/dev/null 2>&1 && break
    sleep 2
  done
  curl -fs "$STINGAR_ES_URL" >/dev/null 2>&1 || { echo "ES not ready" >&2; exit 1; }
  log "Elasticsearch is up"
}

apply_templates() {
  log "Applying scanner-lite index templates..."
  curl -fsS -X PUT "$STINGAR_ES_URL/_index_template/scanner-ip-enrichment" \
    -H "Content-Type: application/json" \
    -d @"$ROOT/es/templates/scanner-ip-enrichment.json" >/dev/null
  curl -fsS -X PUT "$STINGAR_ES_URL/_index_template/scanner-asn-batches" \
    -H "Content-Type: application/json" \
    -d @"$ROOT/es/templates/scanner-asn-batches.json" >/dev/null
  log "Templates applied"
}

start_server() {
  mkdir -p "$ROOT/.run"
  log "Starting scanner-lite API on :$SCANNER_LITE_PORT ..."
  "$PYTHON" -m scanner_lite.server >"$ROOT/.run/scanner-lite.log" 2>&1 &
  echo $! >"$ROOT/.run/scanner-lite.pid"
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
  log "ASN batches:"
  curl -fsS "http://127.0.0.1:$SCANNER_LITE_PORT/scanner-lite/batches/asn" | "$PYTHON" -m json.tool
}

case "${1:-up}" in
  up)
    start_es
    apply_templates
    "$PYTHON" -m scanner_lite.eval.overlap 2>/dev/null || true
    start_server
    demo_events
    log "Logs: .run/scanner-lite.log"
    ;;
  es-only)
    start_es
    apply_templates
    ;;
  *)
    echo "Usage: $0 [up|es-only]" >&2
    exit 1
    ;;
esac
