#!/usr/bin/env bash
# Build threat-intel-agent-lite-51366.tgz for VCM web-console / scp deploy.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/dist/threat-intel-agent-lite-51366.tgz}"

mkdir -p "$(dirname "$OUT")"
tar czf "$OUT" \
  --exclude='.git' \
  --exclude='.venv*' \
  --exclude='__pycache__' \
  --exclude='.run' \
  --exclude='vendor/stingar-ui/node_modules' \
  --exclude='vendor/stingar-ui/.next' \
  --exclude='deploy/stingar/storage' \
  --exclude='dist' \
  -C "$(dirname "$ROOT")" "$(basename "$ROOT")"

echo "Wrote $OUT ($(du -h "$OUT" | awk '{print $1}'))"
echo "Serve: cd $(dirname "$OUT") && python3 -m http.server 18888 --bind 0.0.0.0"
echo "VM console: MAC_HTTP_BASE=http://YOUR_MAC_IP:18888 bash ~/vm-web-console-51366-paste.sh"
