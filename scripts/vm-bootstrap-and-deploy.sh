#!/usr/bin/env bash
# Run ON the Duke VM (after rsync of threat-intel-agent-lite). No Mac Docker required.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY_DIR="$ROOT/deploy/stingar"
UI_TAG="${STINGAR_UI_VERSION:-v2.3}"

log() { echo "[vm-bootstrap] $*"; }

install_docker_if_missing() {
  if command -v docker >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
    log "Docker already installed"
    return 0
  fi
  log "Installing docker.io + docker-compose-v2 (requires sudo once)..."
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    docker.io docker-compose-v2 curl openssl python3 python3-venv python3-pip ca-certificates
  sudo systemctl enable --now docker
  sudo usermod -aG docker "$USER" 2>/dev/null || true
  log "Docker installed: $(docker --version 2>/dev/null || sudo docker --version)"
}

docker_cmd() {
  if docker info >/dev/null 2>&1; then
    docker "$@"
  else
    sudo docker "$@"
  fi
}

ensure_deploy_files() {
  mkdir -p "$DEPLOY_DIR/storage/db" "$DEPLOY_DIR/certs"
  if [[ ! -f "$DEPLOY_DIR/stingar.env" ]]; then
    cp "$DEPLOY_DIR/stingar.env.demo" "$DEPLOY_DIR/stingar.env"
    log "Created stingar.env from demo template"
  fi
  if [[ ! -f "$DEPLOY_DIR/certs/cert.pem" ]]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "$DEPLOY_DIR/certs/key.pem" \
      -out "$DEPLOY_DIR/certs/cert.pem" \
      -subj "/CN=localhost" >/dev/null 2>&1
    log "Generated TLS certs"
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
  echo "Elasticsearch not ready" >&2
  return 1
}

compose_up() {
  ensure_deploy_files
  log "Building stingarui + scanner-lite (first run may take 15–25 min)..."
  (
    cd "$DEPLOY_DIR"
    docker_cmd compose build --build-arg "VERSION=$UI_TAG" stingarui scanner-lite
    docker_cmd compose up -d
  )
  wait_for_es
}

bootstrap_data() {
  export ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://127.0.0.1:9200}"
  export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
  export SCANNER_INVENTORY_BACKEND="${SCANNER_INVENTORY_BACKEND:-redis}"
  export SCANNER_LITE_URL="${SCANNER_LITE_URL:-http://127.0.0.1:8091}"

  PYTHON="${PYTHON:-$ROOT/.venv-demo/bin/python}"
  if [[ ! -x "$PYTHON" ]]; then
    python3 -m venv "$ROOT/.venv-demo"
    PYTHON="$ROOT/.venv-demo/bin/python"
    "$PYTHON" -m pip install -q -U pip
    "$PYTHON" -m pip install -q -r "$ROOT/requirements.txt"
  fi

  "$ROOT/scripts/deploy-stingar-integration.sh" templates
  "$ROOT/scripts/deploy-stingar-integration.sh" seed-redis
  "$ROOT/scripts/deploy-stingar-integration.sh" smoke

  curl -fsS -X POST "$SCANNER_LITE_URL/ingest/fluentd" \
    -H "Content-Type: application/json" \
    -d '{"srcIp":"198.235.24.10","app":"web","hpData":{"eventType":"service_probe"}}' >/dev/null || true
  curl -fsS -X POST "$SCANNER_LITE_URL/ingest/fluentd" \
    -H "Content-Type: application/json" \
    -d '{"app":"peoplesoft","srcIp":"52.29.178.95","hpData":{"method":"HEAD","path":"/ps/signon.html","eventType":"peoplesoft-scan"}}' >/dev/null || true
}

print_done() {
  local host
  host="$(hostname -f 2>/dev/null || hostname)"
  cat <<EOF

================================================================================
Deploy finished on VM.

  UI:  https://${host}/attack-analysis
       (accept self-signed cert if prompted)

  Health: curl -s http://127.0.0.1:8091/health
  Hard refresh browser: Cmd+Shift+R

  OUTCOME column between Location and C2 after ingest + UI rebuild.
================================================================================
EOF
}

main() {
  install_docker_if_missing
  compose_up
  bootstrap_data
  print_done
}

main "$@"
