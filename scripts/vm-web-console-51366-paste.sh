#!/usr/bin/env bash
# Paste this ENTIRE script into the Duke VCM web console for vcm-51366.
# Prerequisite: tarball at ~/threat-intel-agent-lite-51366.tgz
#   (from scp, or: curl -fO http://YOUR_MAC_IP:18888/threat-intel-agent-lite-51366.tgz)
set -euo pipefail

export DUKE_UI_URL="${DUKE_UI_URL:-https://vcm-51366.vm.duke.edu/sessions}"
export REPO_TARBALL="${REPO_TARBALL:-$HOME/threat-intel-agent-lite-51366.tgz}"
export REPO_DIR="${REPO_DIR:-$HOME/threat-intel-agent-lite}"
MAC_HTTP_BASE="${MAC_HTTP_BASE:-}"

if [[ ! -f "$REPO_TARBALL" && -n "$MAC_HTTP_BASE" ]]; then
  echo "Fetching tarball from $MAC_HTTP_BASE ..."
  curl -fSL "${MAC_HTTP_BASE%/}/threat-intel-agent-lite-51366.tgz" -o "$REPO_TARBALL"
fi

if [[ ! -f "$REPO_TARBALL" ]]; then
  echo "Missing $REPO_TARBALL"
  echo "From your Mac (same network/VPN), after HTTP server is running:"
  echo "  export MAC_HTTP_BASE=http://YOUR_MAC_IP:18888"
  echo "  curl -fO \$MAC_HTTP_BASE/threat-intel-agent-lite-51366.tgz"
  echo "Or: MAC_HTTP_BASE=http://YOUR_MAC_IP:18888 bash $0"
  exit 1
fi

cp "$REPO_TARBALL" "$HOME/threat-intel-agent-lite-51366.tgz"
chmod +x "$HOME/threat-intel-agent-lite/scripts/vm-web-console-deploy.sh" 2>/dev/null || true

if [[ -x "$HOME/threat-intel-agent-lite/scripts/vm-web-console-deploy.sh" ]]; then
  exec "$HOME/threat-intel-agent-lite/scripts/vm-web-console-deploy.sh"
fi

# First run: extract tarball then deploy
rm -rf "$REPO_DIR"
mkdir -p "$REPO_DIR"
tar xzf "$REPO_TARBALL" -C "$HOME"
# tarball root is threat-intel-agent-lite/
if [[ ! -d "$REPO_DIR" ]]; then
  echo "ERROR: expected $REPO_DIR after extract" >&2
  exit 1
fi
chmod +x "$REPO_DIR"/scripts/*.sh "$REPO_DIR"/scripts/lib/*.sh 2>/dev/null || true
exec "$REPO_DIR/scripts/vm-web-console-deploy.sh"
