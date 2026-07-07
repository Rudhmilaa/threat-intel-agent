#!/usr/bin/env bash
# One-shot local demo: STINGAR stack + scanner-lite + patched UI + sample data.
# Run from repo root on the SAME machine you open in the browser.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DEPLOY_DIR="${STINGAR_DEPLOY_DIR:-$ROOT/deploy/stingar}"
PYTHON="${PYTHON:-$ROOT/.venv-demo/bin/python}"

log() { echo "[demo-deploy] $*"; }
die() { log "ERROR: $*"; exit 1; }

check_disk() {
  local avail
  avail=$(df -g / 2>/dev/null | awk 'NR==2 {print $4}' || echo 99)
  if [[ "${avail:-0}" -lt 5 ]]; then
    log "WARNING: Less than ~5 GB free on /. Docker builds may fail."
    log "Free space (Trash, Docker prune) or use: ./scripts/deploy-scanner-lite.sh up-native"
  fi
}

docker_quick() {
  perl -e 'alarm shift; exec @ARGV' "$1" docker info >/dev/null 2>&1
}

ensure_docker() {
  if docker_quick 8; then
    return 0
  fi
  log "Starting Docker Desktop..."
  open -a Docker 2>/dev/null || open -a "Docker Desktop" 2>/dev/null || true
  for i in $(seq 1 45); do
    if docker_quick 8; then
      log "Docker ready (${i} attempts)"
      return 0
    fi
    sleep 2
  done
  die "Docker is not running. Start Docker Desktop manually, free disk space (~10 GB), and retry."
}

ensure_python() {
  if [[ -x "$PYTHON" ]]; then
    return 0
  fi
  log "Creating .venv-demo and installing requirements..."
  python3 -m venv "$ROOT/.venv-demo"
  PYTHON="$ROOT/.venv-demo/bin/python"
  "$PYTHON" -m pip install -q --upgrade pip
  "$PYTHON" -m pip install -q -r "$ROOT/requirements.txt"
}

ensure_compose_files() {
  mkdir -p "$DEPLOY_DIR/storage/db" "$DEPLOY_DIR/certs"
  if [[ ! -f "$DEPLOY_DIR/stingar.env" ]]; then
    if [[ -f "$DEPLOY_DIR/stingar.env.demo" ]]; then
      cp "$DEPLOY_DIR/stingar.env.demo" "$DEPLOY_DIR/stingar.env"
    else
      die "Missing $DEPLOY_DIR/stingar.env — copy stingar.env.demo to stingar.env"
    fi
    log "Created $DEPLOY_DIR/stingar.env"
  fi
  if [[ ! -f "$DEPLOY_DIR/certs/cert.pem" ]]; then
    log "Generating self-signed TLS certs..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "$DEPLOY_DIR/certs/key.pem" \
      -out "$DEPLOY_DIR/certs/cert.pem" \
      -subj "/CN=localhost" >/dev/null 2>&1
  fi
}

wait_for_es() {
  local url="${ELASTICSEARCH_URL:-http://127.0.0.1:9200}"
  log "Waiting for Elasticsearch at $url ..."
  for _ in $(seq 1 90); do
    if curl -fs "$url/_cluster/health?wait_for_status=yellow&timeout=5s" >/dev/null 2>&1; then
      log "Elasticsearch is up"
      return 0
    fi
    sleep 3
  done
  die "Elasticsearch not ready at $url — check: cd deploy/stingar && docker compose ps"
}

compose_up() {
  log "Building and starting STINGAR + scanner-lite stack (first run may take 10–20 min)..."
  (
    cd "$DEPLOY_DIR"
    docker compose up -d --build
  )
}

bootstrap_data() {
  export ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://127.0.0.1:9200}"
  export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
  export SCANNER_INVENTORY_BACKEND="${SCANNER_INVENTORY_BACKEND:-redis}"
  export SCANNER_LITE_URL="${SCANNER_LITE_URL:-http://127.0.0.1:8091}"

  "$ROOT/scripts/deploy-stingar-integration.sh" templates
  "$ROOT/scripts/deploy-stingar-integration.sh" seed-redis

  log "Waiting for scanner-lite..."
  for _ in $(seq 1 60); do
    if curl -fs "$SCANNER_LITE_URL/health" >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done

  log "Posting demo ingest events..."
  curl -fsS -X POST "$SCANNER_LITE_URL/ingest/fluentd" \
    -H "Content-Type: application/json" \
    -d '{"srcIp":"198.235.24.10","app":"web","hpData":{"eventType":"service_probe"}}' \
    >/dev/null || log "benign ingest failed (non-fatal)"

  curl -fsS -X POST "$SCANNER_LITE_URL/ingest/fluentd" \
    -H "Content-Type: application/json" \
    -d '{"app":"peoplesoft","srcIp":"52.29.178.95","hpData":{"method":"HEAD","path":"/ps/signon.html","eventType":"peoplesoft-scan"}}' \
    >/dev/null || log "suspicious ingest failed (non-fatal)"

  "$ROOT/scripts/import-stingar-dashboards.sh" 2>/dev/null || log "Kibana dashboard import skipped (non-fatal)"
}

deploy_ui() {
  STINGAR_UI_VERSION="${STINGAR_UI_VERSION:-v2.3}" \
    "$ROOT/scripts/deploy-stingar-ui-vm.sh"
}

print_success() {
  cat <<EOF

================================================================================
Demo deploy complete (run on THIS machine)

  UI (accept self-signed cert):  https://localhost/
  UI direct:                     http://127.0.0.1:3000/
  Kibana:                        http://127.0.0.1:5601/
  scanner-lite health:           curl http://127.0.0.1:8091/health

  Attack Analysis → Overview → OUTCOME column (hard refresh: Cmd+Shift+R)

  Verify sessions in ES:
    curl -s "http://127.0.0.1:9200/stingar-*/_search" \\
      -H "Content-Type: application/json" \\
      -d '{"size":2,"sort":[{"@timestamp":"desc"}],"_source":["src_ip","outcome_category"]}'

  Stop stack:
    cd deploy/stingar && docker compose down

  Full instructions: docs/DEMO-DEPLOY.md
================================================================================
EOF
}

main() {
  check_disk
  ensure_python
  ensure_compose_files

  if [[ "${1:-}" == "ui-only" ]]; then
    ensure_docker
    deploy_ui
    bootstrap_data
    print_success
    exit 0
  fi

  if [[ "${1:-}" == "native" ]]; then
    log "Docker-free path: Elasticsearch native + scanner-lite API (no STINGAR UI)"
    "$ROOT/scripts/deploy-scanner-lite.sh" up-native
    log "For full UI demo when Docker works: ./scripts/demo-deploy-stingar.sh"
    exit 0
  fi

  if ! docker_quick 10; then
    log "Docker not available — falling back to native API demo (no STINGAR UI)."
    log "Free ~10 GB disk, start Docker Desktop, then re-run: $0"
    "$ROOT/scripts/deploy-scanner-lite.sh" up-native
    exit 0
  fi

  compose_up
  wait_for_es
  bootstrap_data
  print_success
}

main "$@"
