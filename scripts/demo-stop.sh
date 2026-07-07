#!/usr/bin/env bash
# Stop local STINGAR demo (native ES + scanner-lite + api + ui + keep-alive).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PID_FILE="$ROOT/.run/elasticsearch-native.pid"

echo "[demo-stop] stopping keep-alive and app processes..."
pkill -f "keep-stingar-demo-alive.sh" 2>/dev/null || true
pkill -f "scanner_lite.server" 2>/dev/null || true
pkill -f "gunicorn.*app:api" 2>/dev/null || true
pkill -f "node start-server.js" 2>/dev/null || true

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  echo "[demo-stop] stopping native Elasticsearch (PID $(cat "$PID_FILE"))..."
  kill "$(cat "$PID_FILE")" 2>/dev/null || true
  rm -f "$PID_FILE"
fi

echo "[demo-stop] done (Redis left running — brew services stop redis to stop it)"
