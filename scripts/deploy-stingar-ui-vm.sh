#!/usr/bin/env bash
# Rebuild and redeploy patched stingar-ui on the STINGAR VM.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY_DIR="${STINGAR_DEPLOY_DIR:-$ROOT/deploy/stingar}"
UI_TAG="${STINGAR_UI_VERSION:-v2.3}"

log() { echo "[deploy-stingar-ui] $*"; }

ensure_deploy_files() {
  mkdir -p "$DEPLOY_DIR/storage/db" "$DEPLOY_DIR/certs"
  if [[ ! -f "$DEPLOY_DIR/stingar.env" ]]; then
    if [[ -f "$DEPLOY_DIR/stingar.env.demo" ]]; then
      cp "$DEPLOY_DIR/stingar.env.demo" "$DEPLOY_DIR/stingar.env"
      log "Created $DEPLOY_DIR/stingar.env from stingar.env.demo"
    else
      cp "$DEPLOY_DIR/base/stingar.env.example" "$DEPLOY_DIR/stingar.env"
      cat "$DEPLOY_DIR/stingar.env.example" >> "$DEPLOY_DIR/stingar.env"
      log "Created $DEPLOY_DIR/stingar.env from examples — review before production use"
    fi
  fi
  if [[ ! -f "$DEPLOY_DIR/certs/cert.pem" || ! -f "$DEPLOY_DIR/certs/key.pem" ]]; then
    log "Generating self-signed TLS certs in $DEPLOY_DIR/certs ..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "$DEPLOY_DIR/certs/key.pem" \
      -out "$DEPLOY_DIR/certs/cert.pem" \
      -subj "/CN=localhost" >/dev/null 2>&1
  fi
}

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  log "Docker is required and must be running."
  exit 1
fi

if [[ ! -f "$ROOT/vendor/stingar-ui/Dockerfile" ]]; then
  log "Missing vendor/stingar-ui — run scripts/extract-stingar-images.sh first."
  exit 1
fi

ensure_deploy_files

log "Building stingarui from vendor/stingar-ui (VERSION=$UI_TAG)..."
(
  cd "$DEPLOY_DIR"
  docker compose build --build-arg "VERSION=$UI_TAG" stingarui
  docker compose up -d stingarui web stingarapi elasticsearch redis scanner-lite fluentd kibana
)

log "Deployed patched UI."
log "  https://localhost/          (via nginx — accept self-signed cert)"
log "  http://127.0.0.1:3000/      (direct UI container)"
log "Hard-refresh Attack Analysis → Overview. OUTCOME column sits between Location and C2."
