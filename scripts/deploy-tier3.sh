#!/usr/bin/env bash
# Tier 3 local deploy: Elasticsearch + templates + central + webhook listener
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PYTHON="${PYTHON:-$ROOT/.venv-1/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
  PYTHON="${PYTHON:-python3}"
fi

export STINGAR_ES_URL="${STINGAR_ES_URL:-http://127.0.0.1:9200}"
export STINGAR_STORAGE_BACKEND=elasticsearch
export CENTRAL_API_KEY="${CENTRAL_API_KEY:-dev-master-key}"
export CENTRAL_ENRICHMENT_URL="${CENTRAL_ENRICHMENT_URL:-http://127.0.0.1:8080}"
export STINGAR_CLIENT_ID="${STINGAR_CLIENT_ID:-example-stingar-01}"
export STINGAR_DEPLOYMENT_MODE="${STINGAR_DEPLOYMENT_MODE:-hybrid}"

log() { echo "[deploy-tier3] $*"; }

ensure_docker() {
  if ! docker info >/dev/null 2>&1; then
    log "Starting Docker Desktop..."
    open -a Docker 2>/dev/null || open -a "Docker Desktop" 2>/dev/null || true
    for _ in $(seq 1 60); do
      docker info >/dev/null 2>&1 && break
      sleep 2
    done
  fi
  docker info >/dev/null 2>&1 || {
    echo "Docker is not running. Start Docker Desktop and retry." >&2
    exit 1
  }
}

start_es() {
  ensure_docker
  log "Starting Elasticsearch..."
  docker compose -f deploy/docker-compose.yml up -d elasticsearch
  log "Waiting for Elasticsearch at $STINGAR_ES_URL ..."
  for _ in $(seq 1 60); do
    if curl -fs "$STINGAR_ES_URL" >/dev/null 2>&1; then
      log "Elasticsearch is up"
      return 0
    fi
    sleep 2
  done
  echo "Elasticsearch did not become ready in time" >&2
  exit 1
}

apply_templates() {
  log "Applying index templates and ILM policy..."
  curl -fsS -X PUT "$STINGAR_ES_URL/_index_template/stingar-enriched" \
    -H "Content-Type: application/json" \
    -d @"$ROOT/es/templates/stingar-enriched.json" >/dev/null
  curl -fsS -X PUT "$STINGAR_ES_URL/_index_template/intel-summaries" \
    -H "Content-Type: application/json" \
    -d @"$ROOT/es/templates/intel-summaries.json" >/dev/null
  curl -fsS -X PUT "$STINGAR_ES_URL/_ilm/policy/stingar-enriched-policy" \
    -H "Content-Type: application/json" \
    -d @"$ROOT/es/ilm/stingar-enriched-policy.json" >/dev/null
  log "Templates applied"
}

start_services() {
  mkdir -p "$ROOT/data" "$ROOT/.run"
  log "Starting central server on :8080 ..."
  "$PYTHON" -m central.server >"$ROOT/.run/central.log" 2>&1 &
  echo $! >"$ROOT/.run/central.pid"

  log "Starting webhook listener on :8090 ..."
  "$PYTHON" -m stingar.webhook_listener >"$ROOT/.run/webhook.log" 2>&1 &
  echo $! >"$ROOT/.run/webhook.pid"

  for _ in $(seq 1 30); do
    curl -fs http://127.0.0.1:8080/health >/dev/null 2>&1 && break
    sleep 1
  done
  curl -fs http://127.0.0.1:8090/health >/dev/null 2>&1 || sleep 2
  log "Services started (PIDs: central=$(cat "$ROOT/.run/central.pid"), webhook=$(cat "$ROOT/.run/webhook.pid"))"
}

send_demo_events() {
  log "Sending demo honeypot events..."
  curl -fsS -X POST http://127.0.0.1:8090/webhook/stingar \
    -H "Content-Type: application/json" \
    -d '{
      "events": [{
        "source_ip": "203.0.113.42",
        "destination_ip": "10.0.0.25",
        "destination_port": 22,
        "attack_type": "ssh_bruteforce",
        "protocol": "ssh",
        "honeypot_type": "cowrie"
      }]
    }' | "$PYTHON" -m json.tool

  echo
  curl -fsS -X POST http://127.0.0.1:8090/webhook/stingar \
    -H "Content-Type: application/json" \
    -d '{
      "events": [{
        "source_ip": "198.235.24.10",
        "destination_ip": "10.0.0.25",
        "destination_port": 8080,
        "attack_type": "service_probe",
        "protocol": "http",
        "honeypot_type": "web"
      }]
    }' | "$PYTHON" -m json.tool
}

show_status() {
  echo
  log "Central health:"
  curl -fsS http://127.0.0.1:8080/health | "$PYTHON" -m json.tool
  echo
  log "Session search (high severity):"
  curl -fsS -H "Authorization: Bearer $CENTRAL_API_KEY" \
    "http://127.0.0.1:8080/api/v1/sessions?q=severity:>=high&hours=24&client_id=$STINGAR_CLIENT_ID" \
    | "$PYTHON" -m json.tool || echo "(session search may be empty on first run)"
  echo
  log "Logs: .run/central.log, .run/webhook.log"
  log "Stop: scripts/stop-tier3.sh"
}

case "${1:-up}" in
  up)
    start_es
    apply_templates
    start_services
    send_demo_events
    show_status
    ;;
  es-only)
    start_es
    apply_templates
    curl -fsS "$STINGAR_ES_URL" | "$PYTHON" -m json.tool
    ;;
  *)
    echo "Usage: $0 [up|es-only]" >&2
    exit 1
    ;;
esac
