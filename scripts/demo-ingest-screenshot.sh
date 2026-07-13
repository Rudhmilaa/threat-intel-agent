#!/usr/bin/env bash
# Post demo events for Attack Analysis OUTCOME screenshots (run ON the STINGAR VM).
set -euo pipefail

SCANNER_LITE_URL="${SCANNER_LITE_URL:-http://127.0.0.1:8091}"
ES_URL="${ELASTICSEARCH_URL:-http://127.0.0.1:9200}"
UI_BASE="${STINGAR_UI_URL:-https://vcm-51366.vm.duke.edu}"

log() { echo "[demo-ingest] $*"; }

if ! curl -fs "${SCANNER_LITE_URL}/health" >/dev/null 2>&1; then
  echo "scanner-lite not reachable at ${SCANNER_LITE_URL}" >&2
  echo "Start the stack first: ./scripts/deploy-stingar-duke-vm.sh full" >&2
  exit 1
fi

log "Health:"
curl -fs "${SCANNER_LITE_URL}/health" | python3 -m json.tool 2>/dev/null || curl -fs "${SCANNER_LITE_URL}/health"
echo

log "Posting benign known scanner (198.235.24.10)..."
curl -fsS -X POST "${SCANNER_LITE_URL}/ingest/fluentd" \
  -H "Content-Type: application/json" \
  -d '{"srcIp":"198.235.24.10","app":"web","hpData":{"eventType":"service_probe"}}'
echo

log "Posting suspicious PeopleSoft probe (52.29.178.95)..."
curl -fsS -X POST "${SCANNER_LITE_URL}/ingest/fluentd" \
  -H "Content-Type: application/json" \
  -d '{"app":"peoplesoft","srcIp":"52.29.178.95","hpData":{"method":"HEAD","path":"/ps/signon.html","eventType":"peoplesoft-scan"}}'
echo

log "Posting c2-engine style cowrie session with payload + playbook (185.196.8.22)..."
curl -fsS -X POST "${SCANNER_LITE_URL}/ingest/fluentd" \
  -H "Content-Type: application/json" \
  -d '{
    "srcIp":"185.196.8.22",
    "app":"cowrie",
    "c2_host":["185.196.8.22"],
    "hpData":{
      "eventType":"cowrie.session",
      "iocs_c2_hosts":["185.196.8.22"],
      "playbook_hash":"9f2c41deadbeef9f2c41deadbeef9f2c41de",
      "playbook_canonical":"wget <URL> -o <TMP>\nchmod +x <TMP>\n./<TMP>",
      "payload_refs":[
        {
          "kind":"download",
          "sha256":"af3c9b1e2ed02578ca1066c8235ba4f991e645f89012406c639dbccc6582eec8",
          "status":"ok",
          "attempted_url":"http://185.196.8.22/armv7l"
        }
      ]
    }
  }'
echo

log "Posting second benign row for a fuller table..."
curl -fsS -X POST "${SCANNER_LITE_URL}/ingest/fluentd" \
  -H "Content-Type: application/json" \
  -d '{"srcIp":"198.235.24.11","app":"web","hpData":{"eventType":"service_probe"}}'
echo

if curl -fs "${ES_URL}" >/dev/null 2>&1; then
  log "Latest sessions in Elasticsearch:"
  curl -fsS "${ES_URL}/stingar-*/_search" \
    -H "Content-Type: application/json" \
    -d '{"size":5,"sort":[{"@timestamp":"desc"}],"_source":["@timestamp","src_ip","app","outcome_category","outcome_summary","hp_data.enrichment.payloads","hp_data.enrichment.playbook"]}' \
    | python3 -m json.tool 2>/dev/null || true
fi

cat <<EOF

Done. Open Attack Analysis and hard-refresh (Cmd+Shift+R):
  ${UI_BASE}/sessions

Expect:
  - OUTCOME: BENIGN (green) for 198.235.x
  - OUTCOME: SUSPICIOUS (amber) for 52.29.178.95
  - OUTCOME popover on 185.196.8.22 shows C2, Payloads, and Playbook sections
EOF
