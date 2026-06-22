# Deployment

How to run central, STINGAR webhook listener, and sync worker.

## Roles

| Service | Command | Default bind |
|---|---|---|
| Central enrichment server | `python -m central.server` | `0.0.0.0:8080` |
| STINGAR webhook listener | `python -m stingar.webhook_listener` | `0.0.0.0:8090` |
| Sync queue drain | `python -m stingar.sync_worker` | one-shot CLI |
| Demo / test suite | `python main.py` | n/a |

## Quick start: hybrid stack

**Terminal 1 — central:**

```bash
source .venv/bin/activate
export STINGAR_STORAGE_BACKEND=elasticsearch   # or sqlite for dev
export CENTRAL_API_KEY=dev-master-key            # optional in dev
python -m central.server
```

**Terminal 2 — STINGAR listener:**

```bash
export CENTRAL_ENRICHMENT_URL=http://127.0.0.1:8080
export STINGAR_CLIENT_ID=example-stingar-01
export CENTRAL_API_KEY=dev-master-key
export STINGAR_DEPLOYMENT_MODE=hybrid
python -m stingar.webhook_listener
```

**Send a test event:**

```bash
curl -X POST http://127.0.0.1:8090/webhook/stingar \
  -H "Content-Type: application/json" \
  -d '{
    "events": [{
      "source_ip": "203.0.113.42",
      "destination_ip": "10.0.0.25",
      "destination_port": 22,
      "attack_type": "ssh_bruteforce",
      "protocol": "ssh",
      "honeypot_type": "cowrie"
    }]
  }'
```

**Drain offline queue (if central was down):**

```bash
python -m stingar.sync_worker
```

## Environment variables

### Storage

| Variable | Default | Purpose |
|---|---|---|
| `STINGAR_STORAGE_BACKEND` | `elasticsearch` | `elasticsearch` or `sqlite` |
| `STINGAR_ES_URL` | `http://127.0.0.1:9200` | Elasticsearch URL |
| `STINGAR_ES_USER` | (none) | ES basic auth user |
| `STINGAR_ES_PASSWORD` | (none) | ES basic auth password |
| `STINGAR_LOCAL_CACHE_PATH` | `data/local_cache.db` | SQLite local cache path |

### STINGAR client / listener

| Variable | Default | Purpose |
|---|---|---|
| `CENTRAL_ENRICHMENT_URL` | (none) | Central server base URL |
| `STINGAR_CLIENT_ID` | `example-stingar-01` | Deployment identifier |
| `STINGAR_SENSOR_ID` | (none) | Default sensor ID for batches |
| `STINGAR_DEPLOYMENT_MODE` | `hybrid` | `hybrid`, `local_only`, or `global_joined` |
| `STINGAR_SYNC_QUEUE_PATH` | `data/sync_queue.db` | Offline sync queue database |
| `STINGAR_WEBHOOK_HOST` | `0.0.0.0` | Webhook listener bind host |
| `STINGAR_WEBHOOK_PORT` | `8090` | Webhook listener bind port |
| `STINGAR_WEBHOOK_SECRET` | (none) | Optional `X-Webhook-Secret` header value |

### Central server

| Variable | Default | Purpose |
|---|---|---|
| `CENTRAL_HOST` | `0.0.0.0` | Bind host |
| `CENTRAL_PORT` | `8080` | Bind port |
| `CENTRAL_API_KEY` | (none) | Master Bearer token |
| `CENTRAL_CLIENT_API_KEYS` | (none) | JSON map `{client_id: api_key}` |
| `CENTRAL_CACHE_BACKEND` | `sqlite` | Cache backend: `sqlite` or `redis` |
| `CENTRAL_CACHE_SQLITE_PATH` | `data/central_cache.db` | SQLite cache path |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis URL when using redis cache |

### LLM / agent

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | (none) | Required for LLM gateway |
| `ABUSEIPDB_API_KEY` | (none) | Live IP reputation (optional) |
| `STINGAR_ENABLE_LLM` | `false` | Must stay false on local nodes |

## API key setup

Auth is disabled when no keys are configured (local dev only).

**Master key** — works for all endpoints:

```bash
export CENTRAL_API_KEY=your-secret-key
```

**Per-client keys** — file or env:

```json
// config/clients/api_keys.json
{
  "clients": {
    "example-stingar-01": "client-specific-key"
  }
}
```

Or:

```bash
export CENTRAL_CLIENT_API_KEYS='{"example-stingar-01":"client-key"}'
```

All protected requests use:

```
Authorization: Bearer <api_key>
```

## Elasticsearch bootstrap

1. Start Elasticsearch 8.x locally or point `STINGAR_ES_URL` at your cluster.

2. Apply index templates:

```bash
curl -X PUT "$STINGAR_ES_URL/_index_template/stingar-enriched" \
  -H "Content-Type: application/json" \
  -d @es/templates/stingar-enriched.json

curl -X PUT "$STINGAR_ES_URL/_index_template/intel-summaries" \
  -H "Content-Type: application/json" \
  -d @es/templates/intel-summaries.json
```

3. Apply ILM policy:

```bash
curl -X PUT "$STINGAR_ES_URL/_ilm/policy/stingar-enriched-policy" \
  -H "Content-Type: application/json" \
  -d @es/ilm/stingar-enriched-policy.json
```

4. Verify:

```bash
curl http://127.0.0.1:8080/health
```

Health response includes `storage_backend` and `elasticsearch.reachable` when ES is configured.

Kibana setup notes: [`es/dashboards/README.md`](../es/dashboards/README.md)

## Test mode (SQLite, no ES)

```bash
STINGAR_STORAGE_BACKEND=sqlite python -m unittest discover -s tests
```

Uses in-memory or file SQLite caches. Session search (`GET /api/v1/sessions`) returns 503 without ES.

## Health checks

| Endpoint | Auth | Returns |
|---|---|---|
| `GET /health` (central) | No | Service status, cache stats, ES reachability |
| `GET /health` (webhook listener) | No | Client ID, deployment mode, sync queue stats |
| `GET /api/v1/cache/stats` | Yes | Cache backend statistics |

## Per-client configuration

Before deploying a new STINGAR node, create:

```
config/clients/{client_id}_sharing_policy.json
config/clients/{client_id}_safelist.json      # optional
config/clients/{client_id}_scanners.json      # optional
```

Copy from `example-stingar-01_*` templates and adjust CIDRs for your network.

## Production notes

- Set `CENTRAL_API_KEY` or per-client keys in production; never rely on auth-disabled mode.
- Use `STINGAR_DEPLOYMENT_MODE=local_only` for air-gapped nodes.
- Set `STINGAR_WEBHOOK_SECRET` on the listener and configure honeypot HTTP output to send it.
- Schedule `python -m stingar.sync_worker` via cron if central uptime is intermittent.
- Scanner feed refresh: weekly CI workflow or `POST /api/v1/scanners/refresh`.

## Related docs

- [API-REFERENCE.md](./API-REFERENCE.md) — endpoint details
- [POLICY-AND-SHARING.md](./POLICY-AND-SHARING.md) — deployment modes
- [DATA-MODEL.md](./DATA-MODEL.md) — ES indices and templates
- [ARCHITECTURE.md](./ARCHITECTURE.md) — topology options
