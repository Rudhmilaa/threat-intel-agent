#!/usr/bin/env bash
# Clear Elasticsearch flood-stage / read-only blocks on low-disk Mac demos.
clear_es_demo_blocks() {
  local es_url="${1:-http://127.0.0.1:9200}"
  curl -fsS -X PUT "$es_url/_cluster/settings" \
    -H "Content-Type: application/json" \
    -d '{"persistent":{"cluster.routing.allocation.disk.threshold_enabled":false}}' \
    >/dev/null 2>&1 || true
  curl -fsS -X PUT "$es_url/_all/_settings" \
    -H "Content-Type: application/json" \
    -d '{"index.blocks.read_only_allow_delete":null,"index.blocks.read_only":null}' \
    >/dev/null 2>&1 || true
  curl -fsS -X PUT "$es_url/stingar-*/_settings" \
    -H "Content-Type: application/json" \
    -d '{"index.blocks.read_only_allow_delete":null}' \
    >/dev/null 2>&1 || true
  curl -fsS -X PUT "$es_url/scanner-*/_settings" \
    -H "Content-Type: application/json" \
    -d '{"index.blocks.read_only_allow_delete":null}' \
    >/dev/null 2>&1 || true
}
