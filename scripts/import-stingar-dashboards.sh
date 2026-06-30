#!/usr/bin/env bash
# Import STINGAR Attack Analysis Kibana saved objects.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KIBANA_URL="${KIBANA_URL:-http://127.0.0.1:5601}"
NDJSON="$ROOT/es/dashboards/stingar/attack-analysis.ndjson"

log() { echo "[import-stingar-dashboards] $*"; }

if [[ ! -f "$NDJSON" ]]; then
  echo "Missing $NDJSON" >&2
  exit 1
fi

for _ in $(seq 1 60); do
  if curl -fs "$KIBANA_URL/api/status" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

curl -fs "$KIBANA_URL/api/status" >/dev/null 2>&1 || {
  echo "Kibana not reachable at $KIBANA_URL" >&2
  exit 1
}

log "Importing Attack Analysis dashboard from attack-analysis.ndjson ..."
response="$(curl -fsS -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  -F "file=@${NDJSON}")"

if echo "$response" | grep -q '"success":true'; then
  log "Import succeeded"
  log "Open dashboard: ${KIBANA_URL}/app/dashboards#/view/stingar-attack-analysis-dashboard"
else
  echo "$response" >&2
  exit 1
fi
