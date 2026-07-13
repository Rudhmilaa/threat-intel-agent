#!/usr/bin/env bash
# Push repo to Duke VM and run bootstrap (Mac: rsync only, no local Docker).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VM_HOST="${DUKE_VM_HOST:-rh386@vcm-51366.vm.duke.edu}"
REMOTE_DIR="${DUKE_VM_DIR:-~/threat-intel-agent-lite}"
DEPLOY_MODE="${DUKE_DEPLOY_MODE:-overlay}"
UI_URL="${DUKE_UI_URL:-https://vcm-51366.vm.duke.edu/sessions}"

log() { echo "[push-to-duke-vm] $*"; }

USE_PASSWORD=0
if [[ -n "${DUKE_VM_PASSWORD:-}" ]]; then
  USE_PASSWORD=1
  export VM_PASS="$DUKE_VM_PASSWORD"
elif ! ssh -o BatchMode=yes -o ConnectTimeout=10 "$VM_HOST" "echo ok" >/dev/null 2>&1; then
  echo "SSH to $VM_HOST failed. Either:" >&2
  echo "  1) Add your public key on the VM (./scripts/duke-vm-ssh-setup.sh), or" >&2
  echo "  2) DUKE_VM_PASSWORD='...' $0" >&2
  exit 1
fi

if ! command -v expect >/dev/null 2>&1; then
  echo "expect is required (preinstalled on macOS)." >&2
  exit 1
fi

RSYNC_EXCLUDES=(
  --exclude ".venv*"
  --exclude ".git"
  --exclude "__pycache__"
  --exclude ".run"
  --exclude "vendor/stingar-ui/node_modules"
  --exclude "vendor/stingar-ui/.next"
  --exclude "deploy/stingar/storage"
)

log "Syncing $ROOT -> $VM_HOST:$REMOTE_DIR"
if [[ "$USE_PASSWORD" -eq 1 ]]; then
  export VM_HOST REMOTE_DIR SRC="$ROOT/"
  expect <<'EXPECT'
set timeout 600
set pass $env(VM_PASS)
set host $env(VM_HOST)
set src $env(SRC)
set dst $env(REMOTE_DIR)

spawn rsync -avz \
  --exclude ".venv*" \
  --exclude ".git" \
  --exclude "__pycache__" \
  --exclude ".run" \
  --exclude "vendor/stingar-ui/node_modules" \
  --exclude "vendor/stingar-ui/.next" \
  --exclude "deploy/stingar/storage" \
  -e "ssh -o StrictHostKeyChecking=accept-new" \
  $src $host:$dst/

expect {
  -re "(?i)password:" { send "$pass\r"; exp_continue }
  eof
}
EXPECT
else
  rsync -avz "${RSYNC_EXCLUDES[@]}" \
    -e "ssh -o StrictHostKeyChecking=accept-new" \
    "$ROOT/" "$VM_HOST:$REMOTE_DIR/"
fi

if [[ "$DEPLOY_MODE" == "overlay" ]]; then
  REMOTE_CMD="chmod +x $REMOTE_DIR/scripts/*.sh $REMOTE_DIR/scripts/lib/*.sh 2>/dev/null; cd $REMOTE_DIR && DUKE_UI_URL='$UI_URL' ./scripts/deploy-stingar-duke-vm.sh full"
  log "Running overlay deploy on existing STINGAR (deploy-stingar-duke-vm.sh)..."
else
  REMOTE_CMD="chmod +x $REMOTE_DIR/scripts/vm-bootstrap-and-deploy.sh && $REMOTE_DIR/scripts/vm-bootstrap-and-deploy.sh"
  log "Running full VM bootstrap (new Docker stack)..."
fi

if [[ "$USE_PASSWORD" -eq 1 ]]; then
  export REMOTE_CMD
  expect <<'EXPECT'
set timeout 3600
set pass $env(VM_PASS)
set host $env(VM_HOST)
set cmd $env(REMOTE_CMD)

spawn ssh -o StrictHostKeyChecking=accept-new $host $cmd

expect {
  -re "(?i)password:" { send "$pass\r"; exp_continue }
  -re {\[sudo\] password.*:} { send "$pass\r"; exp_continue }
  eof
}
EXPECT
else
  ssh -o StrictHostKeyChecking=accept-new "$VM_HOST" "$REMOTE_CMD"
fi

log "Done. Open: $UI_URL"
