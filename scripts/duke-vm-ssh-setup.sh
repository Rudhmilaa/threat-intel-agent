#!/usr/bin/env bash
# Diagnose Duke VCM SSH and print steps to fix "Permission denied (publickey)".
set -euo pipefail

NETID="${DUKE_NETID:-rh386}"
HOST="${DUKE_VCM_HOST:-vcm-51366.vm.duke.edu}"
PUB="${HOME}/.ssh/id_ed25519.pub"
PRIV="${HOME}/.ssh/id_ed25519"

echo "=== Duke VCM SSH setup ==="
echo "Target: ${NETID}@${HOST}"
echo ""

if [[ ! -f "$PUB" ]]; then
  echo "No ${PUB} — generate one:"
  echo "  ssh-keygen -t ed25519 -C \"${NETID}@duke.edu\""
  exit 1
fi

echo "Your public key (add this to Duke + VM if needed):"
echo "----------------------------------------"
cat "$PUB"
echo "----------------------------------------"
echo ""

echo "1) Register at Duke (for NEW VMs and directory):"
echo "   https://idms-web-selfservice.oit.duke.edu/advanced"
echo "   → Manage Your Public SSH Keys → paste key → Add Key"
echo ""
echo "2) EXISTING VM (vcm-51366): keys added AFTER the VM was created"
echo "   are NOT auto-installed. Use VCM web console:"
echo "   https://vcm.duke.edu → your reservation → Console"
echo "   Log in on the VM, then run:"
echo "     mkdir -p ~/.ssh && chmod 700 ~/.ssh"
echo "     echo '$(cat "$PUB")' >> ~/.ssh/authorized_keys"
echo "     chmod 600 ~/.ssh/authorized_keys"
echo ""
echo "3) Optional ~/.ssh/config snippet (repo): deploy/stingar/duke-ssh-config.snippet"
echo ""

if [[ -f "$PRIV" ]]; then
  echo "Testing SSH (BatchMode)..."
  if ssh -o BatchMode=yes -o ConnectTimeout=15 -i "$PRIV" "${NETID}@${HOST}" "echo OK: connected as \$(whoami)@\$(hostname)" 2>/dev/null; then
    echo ""
    echo "SSH works. Deploy on the VM:"
    echo "  ssh ${NETID}@${HOST}"
    echo "  git clone git@gitlab.oit.duke.edu:codeplus2026/ai_tools.git && cd ai_tools"
    echo "  git checkout scanner-enrichment-lite"
    echo "  export STINGAR_ROOT=~/stingar   # adjust"
    echo "  ./scripts/deploy-stingar-duke-vm.sh"
    exit 0
  fi
  echo "SSH still failing (publickey). Complete steps 1–2 above, then re-run this script."
  exit 1
fi

echo "Private key missing at $PRIV"
exit 1
