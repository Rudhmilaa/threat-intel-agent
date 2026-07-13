#!/usr/bin/env bash
# Run ON the Duke VM via VCM web console (paste entire script).
# Installs patched OUTCOME UI + scanner-lite overlay on an existing STINGAR stack.
set -euo pipefail

DUKE_UI_URL="${DUKE_UI_URL:-https://vcm-51366.vm.duke.edu/sessions}"
REPO_DIR="${REPO_DIR:-$HOME/threat-intel-agent-lite}"
GIT_URL="${GIT_URL:-https://gitlab.oit.duke.edu/codeplus2026/ai_tools.git}"
GIT_BRANCH="${GIT_BRANCH:-scanner-enrichment-lite}"

log() { echo "[vm-web-console-deploy] $*"; }

ensure_repo() {
  if [[ -x "$REPO_DIR/scripts/deploy-stingar-duke-vm.sh" ]]; then
    log "Using existing repo at $REPO_DIR"
    return 0
  fi
  log "Cloning $GIT_URL (branch $GIT_BRANCH) -> $REPO_DIR"
  rm -rf "$REPO_DIR"
  git clone --depth 1 --branch "$GIT_BRANCH" "$GIT_URL" "$REPO_DIR"
}

find_stingar_root() {
  if [[ -n "${STINGAR_ROOT:-}" && -f "$STINGAR_ROOT/docker-compose.yml" ]]; then
    return 0
  fi
  for candidate in "$HOME/stingar" "$HOME/Desktop/stingar" /opt/stingar /srv/stingar; do
    if [[ -f "$candidate/docker-compose.yml" ]]; then
      export STINGAR_ROOT="$candidate"
      log "STINGAR_ROOT=$STINGAR_ROOT"
      return 0
    fi
  done
  log "Searching for docker-compose.yml..."
  found="$(find "$HOME" /opt /srv -maxdepth 5 -name docker-compose.yml 2>/dev/null | head -1 || true)"
  if [[ -n "$found" ]]; then
    export STINGAR_ROOT="$(dirname "$found")"
    log "STINGAR_ROOT=$STINGAR_ROOT"
    return 0
  fi
  echo "ERROR: export STINGAR_ROOT=/path/to/stingar (directory with docker-compose.yml)" >&2
  exit 1
}

main() {
  log "hostname=$(hostname) user=$(whoami)"
  docker info >/dev/null 2>&1 || { echo "Start Docker / STINGAR stack first." >&2; exit 1; }
  ensure_repo
  find_stingar_root
  chmod +x "$REPO_DIR"/scripts/*.sh "$REPO_DIR"/scripts/lib/*.sh 2>/dev/null || true
  cd "$REPO_DIR"
  export STINGAR_ROOT DUKE_UI_URL
  ./scripts/deploy-stingar-duke-vm.sh full
}

main "$@"
