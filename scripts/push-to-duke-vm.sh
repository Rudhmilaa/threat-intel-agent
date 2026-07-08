#!/usr/bin/env bash
# Push repo to Duke VM and run bootstrap (Mac: rsync only, no local Docker).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VM_HOST="${DUKE_VM_HOST:-vcm@vcm-53767.vm.duke.edu}"
REMOTE_DIR="${DUKE_VM_DIR:-~/threat-intel-agent-lite}"

log() { echo "[push-to-duke-vm] $*"; }

if [[ -z "${DUKE_VM_PASSWORD:-}" ]]; then
  echo "Set DUKE_VM_PASSWORD for password SSH, or configure SSH keys." >&2
  echo "Example: DUKE_VM_PASSWORD='...' $0" >&2
  exit 1
fi

if ! command -v expect >/dev/null 2>&1; then
  echo "expect is required (preinstalled on macOS)." >&2
  exit 1
fi

log "Syncing $ROOT -> $VM_HOST:$REMOTE_DIR"
export VM_PASS="$DUKE_VM_PASSWORD"
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

log "Running bootstrap on VM (Docker install + compose + OUTCOME UI)..."
expect <<'EXPECT'
set timeout 3600
set pass $env(VM_PASS)
set host $env(VM_HOST)
set dst $env(REMOTE_DIR)

spawn ssh -o StrictHostKeyChecking=accept-new $host "chmod +x $dst/scripts/vm-bootstrap-and-deploy.sh && $dst/scripts/vm-bootstrap-and-deploy.sh"

expect {
  -re "(?i)password:" { send "$pass\r"; exp_continue }
  -re {\[sudo\] password.*:} { send "$pass\r"; exp_continue }
  eof
}
EXPECT

log "Done. Open: https://vcm-53767.vm.duke.edu/attack-analysis"
