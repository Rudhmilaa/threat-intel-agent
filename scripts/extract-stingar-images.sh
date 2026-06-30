#!/usr/bin/env bash
# Extract stingar-ui and stingar-api application trees from 4warned v2.3 images.
# Prefers crane (works without a running Docker daemon); falls back to docker pull/cp.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TAG="${STINGAR_IMAGE_TAG:-v2.3}"
UI_IMAGE="4warned/stingar-ui:${TAG}"
API_IMAGE="4warned/stingar-api:${TAG}"
VENDOR_UI="$ROOT/vendor/stingar-ui"
VENDOR_API="$ROOT/vendor/stingar-api"
TMP="$ROOT/.tmp/stingar-export"
UI_TAR="$TMP/stingar-ui.tar"
API_TAR="$TMP/stingar-api.tar"

log() { echo "[extract-stingar-images] $*"; }

write_manifest() {
  local component=$1 image=$2 dest=$3 digest=""
  if command -v crane >/dev/null 2>&1; then
    digest="$(crane digest "$image" 2>/dev/null || true)"
  fi
  cat >"$dest/MANIFEST.json" <<EOF
{
  "component": "${component}",
  "image": "${image}",
  "tag": "${TAG}",
  "digest": "${digest}",
  "extracted_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "method": "${EXTRACT_METHOD:-unknown}"
}
EOF
}

extract_with_crane() {
  command -v crane >/dev/null 2>&1 || return 1
  EXTRACT_METHOD=crane
  log "Exporting images with crane..."
  mkdir -p "$TMP"
  crane export "$UI_IMAGE" "$UI_TAR"
  crane export "$API_IMAGE" "$API_TAR"

  local ui_root="$TMP/ui-root" api_root="$TMP/api-root"
  rm -rf "$ui_root" "$api_root"
  mkdir -p "$ui_root" "$api_root"
  tar -xf "$UI_TAR" -C "$ui_root"
  tar -xf "$API_TAR" -C "$api_root"

  mkdir -p "$VENDOR_UI" "$VENDOR_API"
  rsync -a --delete \
    --exclude node_modules --exclude .next --exclude __pycache__ \
    "$ui_root/app/" "$VENDOR_UI/"
  rsync -a --delete --exclude __pycache__ \
    "$api_root/apiarist/" "$VENDOR_API/"

  rm -rf "$TMP"
  return 0
}

extract_with_docker() {
  command -v docker >/dev/null 2>&1 || return 1
  docker info >/dev/null 2>&1 || return 1
  EXTRACT_METHOD=docker
  log "Pulling images with docker..."
  docker pull "$UI_IMAGE"
  docker pull "$API_IMAGE"

  local ui_c="stingar-extract-ui-$$" api_c="stingar-extract-api-$$"
  docker create --name "$ui_c" "$UI_IMAGE" >/dev/null
  docker create --name "$api_c" "$API_IMAGE" >/dev/null

  local ui_workdir api_workdir
  ui_workdir="$(docker inspect --format '{{.Config.WorkingDir}}' "$ui_c")"
  api_workdir="$(docker inspect --format '{{.Config.WorkingDir}}' "$api_c")"
  ui_workdir="${ui_workdir:-/app}"
  api_workdir="${api_workdir:-/app}"

  mkdir -p "$VENDOR_UI" "$VENDOR_API"
  docker cp "$ui_c:${ui_workdir}/." "$VENDOR_UI/"
  docker cp "$api_c:/apiarist/." "$VENDOR_API/" 2>/dev/null \
    || docker cp "$api_c:${api_workdir}/." "$VENDOR_API/"

  docker rm "$ui_c" "$api_c" >/dev/null
  return 0
}

main() {
  if extract_with_crane; then
    log "Extracted via crane"
  elif extract_with_docker; then
    log "Extracted via docker"
  else
    echo "Need crane (brew install crane) or a running Docker daemon." >&2
    exit 1
  fi

  write_manifest "stingar-ui" "$UI_IMAGE" "$VENDOR_UI"
  write_manifest "stingar-api" "$API_IMAGE" "$VENDOR_API"
  log "UI -> $VENDOR_UI"
  log "API -> $VENDOR_API"
}

main "$@"
