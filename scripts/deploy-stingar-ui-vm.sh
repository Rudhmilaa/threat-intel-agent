#!/usr/bin/env bash
# Rebuild and redeploy patched stingar-ui on the STINGAR VM.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEPLOY_DIR="${STINGAR_DEPLOY_DIR:-$ROOT/deploy/stingar}"
UI_TAG="${STINGAR_UI_VERSION:-v2.3}"

log() { echo "[deploy-stingar-ui] $*"; }

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  log "Docker is required and must be running."
  exit 1
fi

if [[ ! -f "$ROOT/vendor/stingar-ui/Dockerfile" ]]; then
  log "Missing vendor/stingar-ui — run scripts/extract-stingar-images.sh first."
  exit 1
fi

log "Building stingarui from vendor/stingar-ui (VERSION=$UI_TAG)..."
(
  cd "$DEPLOY_DIR"
  docker compose build --build-arg "VERSION=$UI_TAG" stingarui
  docker compose up -d stingarui
)

log "Deployed. Hard-refresh Attack Analysis → Overview in the browser."
log "Verify OUTCOME column between Location and C2 with hover metadata popover."
