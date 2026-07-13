#!/usr/bin/env bash
# Wait for rh386 SSH on vcm-51366, then rsync repo and run deploy-stingar-duke-vm.sh full.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VM_HOST="rh386@vcm-51366.vm.duke.edu"
# Ignore inherited DUKE_VM_HOST=vcm@... — 51366 is publickey-only for rh386.
UI_URL="${DUKE_UI_URL:-https://vcm-51366.vm.duke.edu/sessions}"
PUB="${HOME}/.ssh/id_ed25519.pub"
TRIES="${SSH_WAIT_TRIES:-60}"
SLEEP="${SSH_WAIT_SLEEP:-10}"

log() { echo "[wait-ssh-push-51366] $*"; }

if [[ ! -f "$PUB" ]]; then
  echo "Missing $PUB — run ssh-keygen first." >&2
  exit 1
fi

log "Target: $VM_HOST"
log "If SSH fails, paste this in the VCM web console (https://vcm.duke.edu → Console):"
echo "----------------------------------------"
cat <<EOF
mkdir -p ~/.ssh && chmod 700 ~/.ssh
grep -qF '$(cat "$PUB")' ~/.ssh/authorized_keys 2>/dev/null || echo '$(cat "$PUB")' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
echo "SSH key installed for \$(whoami)"
EOF
echo "----------------------------------------"

for i in $(seq 1 "$TRIES"); do
  if ssh -o BatchMode=yes -o ConnectTimeout=8 "$VM_HOST" "echo ok" >/dev/null 2>&1; then
    log "SSH ready (attempt $i). Running push-to-duke-vm.sh..."
    export DUKE_VM_HOST="$VM_HOST" DUKE_UI_URL="$UI_URL" DUKE_DEPLOY_MODE=overlay
    exec "$ROOT/scripts/push-to-duke-vm.sh"
  fi
  log "Waiting for SSH... ($i/$TRIES)"
  sleep "$SLEEP"
done

log "Timed out. Add the SSH key via web console, then re-run: $0"
exit 1
