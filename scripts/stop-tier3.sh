#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

stop_pid() {
  local name="$1"
  local pidfile="$ROOT/.run/${name}.pid"
  if [[ -f "$pidfile" ]]; then
    local pid
    pid="$(cat "$pidfile")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      echo "Stopped $name (pid $pid)"
    fi
    rm -f "$pidfile"
  fi
}

stop_pid central
stop_pid webhook

if docker info >/dev/null 2>&1; then
  docker compose -f deploy/docker-compose.yml down 2>/dev/null || true
  echo "Stopped Elasticsearch container"
fi
