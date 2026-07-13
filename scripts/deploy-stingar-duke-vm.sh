#!/usr/bin/env bash
# Deploy scanner-lite + patched OUTCOME UI onto an EXISTING Duke STINGAR VM.
#
# Run this script ON the VM (SSH), not on your laptop:
#   ssh you@vcm-51366.vm.duke.edu
#   git clone ... && cd ai_tools && git checkout scanner-enrichment-lite
#   export STINGAR_ROOT=/path/to/your/stingar/compose
#   ./scripts/deploy-stingar-duke-vm.sh
#
# Then open: https://vcm-51366.vm.duke.edu/sessions (hard refresh)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STINGAR_ROOT="${STINGAR_ROOT:-}"
DUKE_UI_URL="${DUKE_UI_URL:-https://vcm-51366.vm.duke.edu/sessions}"
OVERLAY="$ROOT/deploy/stingar/duke-vm.overlay.yml"
PYTHON="${PYTHON:-$ROOT/.venv-demo/bin/python}"

export ELASTICSEARCH_URL="${ELASTICSEARCH_URL:-http://127.0.0.1:9200}"
export REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
export SCANNER_LITE_URL="${SCANNER_LITE_URL:-http://127.0.0.1:8091}"
export SCANNER_INVENTORY_BACKEND="${SCANNER_INVENTORY_BACKEND:-redis}"

log() { echo "[deploy-stingar-duke-vm] $*"; }

usage() {
  cat <<EOF
Usage: $0 [full|overlay|bootstrap|ingest|ui]

Run ON the Duke STINGAR VM after SSH — not on your Mac.

Required:
  export STINGAR_ROOT=/path/to/existing/stingar/docker-compose/dir

Optional:
  DUKE_UI_URL=https://vcm-51366.vm.duke.edu/sessions

Commands:
  full       overlay + bootstrap + demo ingest (default)
  overlay    docker compose overlay only (scanner-lite, fluentd, stingarui)
  bootstrap  ES templates + Redis seed + smoke
  ingest     post demo events
  ui         rebuild stingarui only

Docs: docs/DEMO-DEPLOY.md#duke-vm-existing-stingar
EOF
}

find_stingar_root() {
  if [[ -n "$STINGAR_ROOT" && -f "$STINGAR_ROOT/docker-compose.yml" ]]; then
    return 0
  fi
  for candidate in \
    "$ROOT/deploy/stingar" \
    "$HOME/threat-intel-agent-lite/deploy/stingar" \
    "$HOME/stingar" \
    "$HOME/Desktop/stingar" \
    "/opt/stingar" \
    "/srv/stingar"; do
    if [[ -f "$candidate/docker-compose.yml" ]]; then
      STINGAR_ROOT="$candidate"
      export STINGAR_ROOT
      log "Using STINGAR_ROOT=$STINGAR_ROOT"
      return 0
    fi
  done
  echo "ERROR: Set STINGAR_ROOT to the directory that contains your running docker-compose.yml" >&2
  echo "Example: export STINGAR_ROOT=~/stingar" >&2
  exit 1
}

ensure_docker() {
  if docker info >/dev/null 2>&1; then
    return 0
  fi
  echo "Docker is not running on this VM. Start the STINGAR stack first." >&2
  exit 1
}

ensure_python() {
  if [[ -x "$PYTHON" ]]; then
    return 0
  fi
  log "Creating .venv-demo..."
  python3 -m venv "$ROOT/.venv-demo"
  PYTHON="$ROOT/.venv-demo/bin/python"
  "$PYTHON" -m pip install -q -U pip
  "$PYTHON" -m pip install -q -r "$ROOT/requirements.txt"
}

overlay_deploy() {
  find_stingar_root
  ensure_docker
  if [[ ! -f "$ROOT/vendor/stingar-ui/Dockerfile" ]]; then
    echo "Missing vendor/stingar-ui — git checkout scanner-enrichment-lite fully." >&2
    exit 1
  fi
  export SCANNER_LITE_BUILD_CONTEXT="$ROOT"
  if [[ "$(cd "$ROOT/deploy/stingar" && pwd)" != "$(cd "$STINGAR_ROOT" && pwd)" ]]; then
    log "Installing patched fluentd.conf into $STINGAR_ROOT"
    cp "$ROOT/deploy/stingar/fluentd.conf" "$STINGAR_ROOT/fluentd.conf"
  else
    log "STINGAR_ROOT is repo deploy/stingar — fluentd.conf already in place"
  fi
  log "Building scanner-lite + stingarui and restarting fluentd..."
  (
    cd "$STINGAR_ROOT"
    docker compose -f docker-compose.yml -f "$OVERLAY" up -d --build scanner-lite fluentd stingarui
  )
  log "Waiting for Elasticsearch..."
  for _ in $(seq 1 60); do
    curl -fs "$ELASTICSEARCH_URL/_cluster/health?wait_for_status=yellow&timeout=5s" >/dev/null 2>&1 && break
    sleep 3
  done
}

bootstrap() {
  ensure_python
  "$ROOT/scripts/deploy-stingar-integration.sh" templates
  "$ROOT/scripts/deploy-stingar-integration.sh" seed-redis
  "$ROOT/scripts/deploy-stingar-integration.sh" smoke
}

demo_ingest() {
  chmod +x "$ROOT/scripts/demo-ingest-screenshot.sh"
  STINGAR_UI_URL="${DUKE_UI_URL%/sessions}/sessions" \
    SCANNER_LITE_URL="$SCANNER_LITE_URL" \
    ELASTICSEARCH_URL="$ELASTICSEARCH_URL" \
    "$ROOT/scripts/demo-ingest-screenshot.sh"
}

ui_only() {
  find_stingar_root
  export SCANNER_LITE_BUILD_CONTEXT="$ROOT"
  (
    cd "$STINGAR_ROOT"
    docker compose -f docker-compose.yml -f "$OVERLAY" build --build-arg "VERSION=${STINGAR_UI_VERSION:-v2.3}" stingarui
    docker compose -f docker-compose.yml -f "$OVERLAY" up -d stingarui
  )
}

print_done() {
  cat <<EOF

================================================================================
Duke VM deploy finished.

  Open in browser (on any machine with VPN/campus access):
    $DUKE_UI_URL

  Hard refresh: Cmd+Shift+R / Ctrl+Shift+R
  OUTCOME column replaces SEVERITY; hover shows scanner metadata plus C2/payload/playbook when present.

  On the VM:
    curl -s $SCANNER_LITE_URL/health | python3 -m json.tool
    curl -s "$ELASTICSEARCH_URL/stingar-*/_search" -H "Content-Type: application/json" \\
      -d '{"size":2,"sort":[{"@timestamp":"desc"}],"_source":["src_ip","outcome_category"]}'

  Do NOT run ./scripts/deploy-stingar-demo.sh on your laptop expecting the VM to update.
================================================================================
EOF
}

main() {
  case "${1:-full}" in
    full)
      overlay_deploy
      bootstrap
      demo_ingest
      print_done
      ;;
    overlay)
      overlay_deploy
      ;;
    bootstrap)
      bootstrap
      ;;
    ingest)
      demo_ingest
      ;;
    ui)
      ui_only
      print_done
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
