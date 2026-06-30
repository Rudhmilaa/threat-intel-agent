#!/usr/bin/env bash
# Start Elasticsearch without Docker (Homebrew elastic/tap/elasticsearch-full).
# Use when Docker Desktop won't launch — usually disk full (FILE_ERROR_NO_SPACE).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ES_URL="${STINGAR_ES_URL:-${ELASTICSEARCH_URL:-http://127.0.0.1:9200}}"
PID_FILE="$ROOT/.run/elasticsearch-native.pid"
LOG_DIR="$ROOT/.run"

log() { echo "[start-elasticsearch-native] $*"; }

mkdir -p "$LOG_DIR"

if curl -fs "$ES_URL" >/dev/null 2>&1; then
  log "Elasticsearch already reachable at $ES_URL"
  curl -fs "$ES_URL" | python3 -m json.tool 2>/dev/null || curl -fs "$ES_URL"
  exit 0
fi

if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew required. Install from https://brew.sh" >&2
  exit 1
fi

if ! brew list elastic/tap/elasticsearch-full >/dev/null 2>&1; then
  log "Installing elasticsearch-full (one-time, ~250MB)..."
  brew tap elastic/tap
  brew install elastic/tap/elasticsearch-full
fi

ES_BIN="$(brew --prefix elastic/tap/elasticsearch-full)/bin/elasticsearch"

if [[ -z "${ES_JAVA_HOME:-}" ]]; then
  if [[ -d "/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home" ]]; then
    ES_JAVA_HOME="/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home"
  elif /usr/libexec/java_home -v 17 >/dev/null 2>&1; then
    ES_JAVA_HOME="$(/usr/libexec/java_home -v 17)"
  else
    echo "Java 17+ required. Install: brew install openjdk@17" >&2
    exit 1
  fi
fi
export ES_JAVA_HOME

brew services stop elastic/tap/elasticsearch-full >/dev/null 2>&1 || true

# Default brew heap is 4GB — too large when disk is nearly full.
export ES_JAVA_OPTS="${ES_JAVA_OPTS:--Xms256m -Xmx512m}"

log "Starting Elasticsearch (heap 512m, no Docker)..."
log "Java: $ES_JAVA_HOME"

if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
  kill "$(cat "$PID_FILE")" 2>/dev/null || true
  sleep 2
fi

# -d daemon mode is unreliable on some Mac setups; use nohup instead.
nohup "$ES_BIN" \
  -E cluster.name=scanner-lite-demo \
  -E discovery.type=single-node \
  -E network.host=127.0.0.1 \
  -E http.port=9200 \
  -E xpack.security.enabled=false \
  -E xpack.ml.enabled=false \
  >>"$LOG_DIR/elasticsearch-native.log" 2>&1 &
echo $! >"$PID_FILE"

for i in $(seq 1 60); do
  if curl -fs "$ES_URL" >/dev/null 2>&1; then
    log "Elasticsearch is up at $ES_URL (after ${i}s)"
    curl -fs "$ES_URL" | python3 -m json.tool 2>/dev/null || curl -fs "$ES_URL"
    log "PID $(cat "$PID_FILE")  logs: $LOG_DIR/elasticsearch-native.log"
    exit 0
  fi
  if [[ -f "$PID_FILE" ]] && ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "Elasticsearch exited early. Last log lines:" >&2
    tail -25 "$LOG_DIR/elasticsearch-native.log" >&2
    exit 1
  fi
  sleep 2
done

echo "Elasticsearch did not become ready at $ES_URL" >&2
tail -25 "$LOG_DIR/elasticsearch-native.log" >&2 || true
exit 1
