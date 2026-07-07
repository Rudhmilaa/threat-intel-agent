#!/usr/bin/env bash
# One-command local STINGAR + scanner-lite demo (OUTCOME column + sample ingest).
# Run from repo root: ./scripts/deploy-stingar-demo.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DEPLOY_DIR="${STINGAR_DEPLOY_DIR:-$ROOT/deploy/stingar}"
PYTHON="${PYTHON:-$ROOT/.venv-demo/bin/python}"
UI_TAG="${STINGAR_UI_VERSION:-v2.3}"

export ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://127.0.0.1:9200}"
export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
export SCANNER_INVENTORY_BACKEND="${SCANNER_INVENTORY_BACKEND:-redis}"
export SCANNER_LITE_URL="${SCANNER_LITE_URL:-http://127.0.0.1:8091}"

log() { echo "[deploy-stingar-demo] $*"; }

if [[ -z "${STINGAR_LOCAL_DEMO_OK:-}" ]]; then
  log "NOTE: For an existing Duke VM (e.g. vcm-51366.vm.duke.edu), SSH to the VM and run:"
  log "      ./scripts/deploy-stingar-duke-vm.sh   (see docs/DEMO-DEPLOY.md)"
  log "      This script is for a full local localhost stack only."
  echo ""
fi

check_disk() {
  local avail_kb avail_h
  avail_kb=$(df -k /System/Volumes/Data 2>/dev/null | awk 'NR==2 {print $4}' || df -k / | awk 'NR==2 {print $4}')
  avail_h=$(df -h /System/Volumes/Data 2>/dev/null | awk 'NR==2 {print $4}' || df -h / | awk 'NR==2 {print $4}')
  log "Disk free: ${avail_h:-unknown}"
  if [[ -n "$avail_kb" && "$avail_kb" -lt 10485760 ]]; then
    echo "" >&2
    echo "ERROR: Need at least ~10 GB free for the full STINGAR Docker demo (UI build + images)." >&2
    echo "Current free space is too low. Empty Trash, remove large files, then:" >&2
    echo "  docker system prune -a    # optional: reclaim Docker disk" >&2
    echo "  ./scripts/deploy-scanner-lite.sh up-native   # lighter demo without full UI" >&2
    echo "See docs/DEMO-DEPLOY.md" >&2
    exit 1
  fi
}

ensure_docker() {
  if docker info >/dev/null 2>&1; then
    return 0
  fi
  log "Docker not ready — trying to start Docker Desktop..."
  open -a Docker 2>/dev/null || open -a "/Applications/Docker.app" 2>/dev/null || true
  for i in $(seq 1 45); do
    if docker info >/dev/null 2>&1; then
      log "Docker ready after ${i}s"
      return 0
    fi
    sleep 2
  done
  echo "Docker daemon not running. Start Docker Desktop manually, free disk space, then retry." >&2
  exit 1
}

ensure_deploy_files() {
  mkdir -p "$DEPLOY_DIR/storage/db" "$DEPLOY_DIR/certs"
  if [[ ! -f "$DEPLOY_DIR/stingar.env" ]]; then
    if [[ -f "$DEPLOY_DIR/stingar.env.demo" ]]; then
      cp "$DEPLOY_DIR/stingar.env.demo" "$DEPLOY_DIR/stingar.env"
      log "Created stingar.env from stingar.env.demo"
    else
      echo "Missing $DEPLOY_DIR/stingar.env.demo" >&2
      exit 1
    fi
  fi
  if [[ ! -f "$DEPLOY_DIR/certs/cert.pem" ]]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "$DEPLOY_DIR/certs/key.pem" \
      -out "$DEPLOY_DIR/certs/cert.pem" \
      -subj "/CN=localhost" >/dev/null 2>&1
    log "Generated self-signed TLS certs in deploy/stingar/certs/"
  fi
}

ensure_python() {
  if [[ -x "$PYTHON" ]]; then
    return 0
  fi
  log "Creating .venv-demo and installing requirements..."
  python3 -m venv "$ROOT/.venv-demo"
  PYTHON="$ROOT/.venv-demo/bin/python"
  "$PYTHON" -m pip install -q -U pip
  "$PYTHON" -m pip install -q -r "$ROOT/requirements.txt"
}

wait_for_es() {
  log "Waiting for Elasticsearch at $ELASTICSEARCH_URL ..."
  for _ in $(seq 1 90); do
    if curl -fs "$ELASTICSEARCH_URL/_cluster/health?wait_for_status=yellow&timeout=5s" >/dev/null 2>&1; then
      log "Elasticsearch is up"
      return 0
    fi
    sleep 3
  done
  echo "Elasticsearch did not become ready at $ELASTICSEARCH_URL" >&2
  exit 1
}

compose_up() {
  ensure_docker
  ensure_deploy_files
  if [[ ! -f "$ROOT/vendor/stingar-ui/Dockerfile" ]]; then
    echo "Missing vendor/stingar-ui — checkout scanner-enrichment-lite branch fully." >&2
    exit 1
  fi
  log "Building and starting STINGAR + scanner-lite stack (first run may take 10–20 min)..."
  (
    cd "$DEPLOY_DIR"
    docker compose build --build-arg "VERSION=$UI_TAG" stingarui scanner-lite
    docker compose up -d
  )
  wait_for_es
}

bootstrap_data() {
  ensure_python
  "$ROOT/scripts/deploy-stingar-integration.sh" templates
  "$ROOT/scripts/deploy-stingar-integration.sh" seed-redis
  "$ROOT/scripts/deploy-stingar-integration.sh" smoke
}

demo_ingest() {
  if ! curl -fs "$SCANNER_LITE_URL/health" >/dev/null 2>&1; then
    log "scanner-lite not reachable — skip demo ingest"
    return 0
  fi
  log "Posting demo events (benign scanner + suspicious probe)..."
  curl -fsS -X POST "$SCANNER_LITE_URL/ingest/fluentd" \
    -H "Content-Type: application/json" \
    -d '{"srcIp":"198.235.24.10","app":"web","hpData":{"eventType":"service_probe"}}' >/dev/null || true
  curl -fsS -X POST "$SCANNER_LITE_URL/ingest/fluentd" \
    -H "Content-Type: application/json" \
    -d '{"app":"peoplesoft","srcIp":"52.29.178.95","hpData":{"method":"HEAD","path":"/ps/signon.html","eventType":"peoplesoft-scan"}}' >/dev/null || true
  log "Demo ingest complete"
}

print_done() {
  cat <<EOF

================================================================================
STINGAR demo deploy finished.

  UI (accept self-signed cert):  https://localhost/
  UI direct:                     http://127.0.0.1:3000/
  Kibana:                        http://127.0.0.1:5601/
  scanner-lite health:           curl $SCANNER_LITE_URL/health

  In browser: Attack Analysis → Overview → OUTCOME column (hard refresh: Cmd+Shift+R)

  Verify sessions in ES:
    curl -s "$ELASTICSEARCH_URL/stingar-*/_search" -H "Content-Type: application/json" \\
      -d '{"size":3,"sort":[{"@timestamp":"desc"}],"_source":["src_ip","outcome_category"]}'

  Full guide: docs/DEMO-DEPLOY.md
================================================================================
EOF
}

usage() {
  cat <<EOF
Usage: $0 [full|compose|bootstrap|ingest|ui-only]

  full       Default — compose up, templates, redis, smoke, demo ingest
  compose    Docker compose build + up only
  bootstrap  ES templates + Redis seed + smoke (stack must be running)
  ingest     Post demo fluentd events only
  ui-only    Rebuild/restart stingarui + deps (uses deploy-stingar-ui-vm.sh)

Run on the SAME machine whose URL you open in the browser.
EOF
}

main() {
  check_disk
  case "${1:-full}" in
    full)
      compose_up
      bootstrap_data
      demo_ingest
      print_done
      ;;
    compose)
      compose_up
      ;;
    bootstrap)
      wait_for_es
      bootstrap_data
      ;;
    ingest)
      demo_ingest
      ;;
    ui-only)
      exec "$ROOT/scripts/deploy-stingar-ui-vm.sh"
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage >&2
      exit 1
      ;;
  esac
}

main "$@"
