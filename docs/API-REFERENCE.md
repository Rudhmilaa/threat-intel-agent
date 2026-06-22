# API Reference

REST endpoints for the central enrichment server and local webhook listener.

Base URL (central): `http://<host>:8080` (default)

Base URL (local listener): `http://<host>:8090` (default)

## Authentication

Protected endpoints require a Bearer token when keys are configured:

```
Authorization: Bearer <api_key>
```

| Key type | Config | Scope |
|---|---|---|
| Master key | `CENTRAL_API_KEY` | All endpoints, all clients |
| Per-client key | `config/clients/api_keys.json` or `CENTRAL_CLIENT_API_KEYS` | Matched by `client_id` in request |

If no keys are configured, auth is disabled (local development only).

Implementation: `central/auth.py`

---

## Health

### GET /health

**Auth:** No

**Service:** Central

Returns service status, storage backend, cache stats, and Elasticsearch reachability.

---

## Enrichment

### POST /api/v1/enrich/events

**Auth:** Yes | **Caller:** STINGAR client (direct central path)

Enriches a batch of honeypot events on central. Auto-detects new IPs when `new_ips` is empty and cache supports it.

**Request body:**

```json
{
  "client_id": "example-stingar-01",
  "sensor_id": "stingar-duke-sensor-01",
  "events": [{ "source_ip": "203.0.113.42", "...": "..." }],
  "new_ips": ["203.0.113.42"]
}
```

**Response:** Enriched documents, batch summary, incident clusters, prioritized incidents, enrichment stats, cache stats, ES stats.

### POST /api/v1/enrich/ip

**Auth:** Yes

Single IP intelligence summary (no honeypot event context).

**Request body:**

```json
{
  "client_id": "example-stingar-01",
  "ip_address": "203.0.113.42"
}
```

### POST /api/v1/enrich/ips

**Auth:** Yes

Batch IP summaries.

**Request body:**

```json
{
  "client_id": "example-stingar-01",
  "ip_addresses": ["203.0.113.42", "198.51.100.17"]
}
```

---

## Webhooks

### POST /api/v1/webhooks/stingar

**Auth:** Yes | **Caller:** STINGAR pushing to central

**Request body:** Must include `client_id` and `events[]`. Central auto-detects new IPs.

### POST /api/v1/webhooks/stingar/{client_id}

**Auth:** Yes

Same as above; `client_id` in URL path.

### POST /webhook/stingar

**Auth:** Optional `X-Webhook-Secret` header | **Service:** Local listener (`stingar/webhook_listener.py`)

Local-first enrichment path. Uses `HybridEnrichmentClient.process_events()`.

**Request body:**

```json
{
  "events": [{ "source_ip": "203.0.113.42", "...": "..." }]
}
```

**Response:** Local enrichment result + sync status (`synced`, `queued`, `skipped`, `blocked`).

---

## Sync

### POST /api/v1/sync/events

**Auth:** Yes | **Caller:** HybridEnrichmentClient, sync_worker

Receives pre-enriched, sanitized documents from local nodes. Re-validates sharing policy on central.

**Request body:**

```json
{
  "client_id": "example-stingar-01",
  "sensor_id": "stingar-duke-sensor-01",
  "enriched_documents": [{ "...": "..." }],
  "batch_summary": {},
  "incident_clusters": [],
  "prioritized_incidents": [],
  "enrichment_stats": {},
  "enrichment_source": "local"
}
```

**Response:**

```json
{
  "sync_status": "accepted",
  "documents_received": 5,
  "documents_accepted": 4,
  "documents_rejected": 1,
  "summaries_merged": 4,
  "es_stats": {},
  "cache_stats": {}
}
```

**Errors:** `403` if all documents rejected by central policy validation.

---

## Sessions search

### GET /api/v1/sessions

**Auth:** Yes | **Requires:** `STINGAR_STORAGE_BACKEND=elasticsearch`

**Query params:**

| Param | Default | Description |
|---|---|---|
| `q` | `""` | Session query string (see DATA-MODEL.md) |
| `client_id` | (none) | Filter by deployment |
| `hours` | `24` | Time window |
| `size` | `50` | Max results |

**Example:**

```
GET /api/v1/sessions?q=severity:>=high&hours=24&client_id=example-stingar-01
```

---

## Policy

### GET /api/v1/clients/{client_id}/policy

**Auth:** Yes

Returns deployment mode, sharing rules, safelist summary.

### PUT /api/v1/clients/{client_id}/policy

**Auth:** Yes

**Request body** (all fields optional):

```json
{
  "deployment_mode": "hybrid",
  "global_joined": false,
  "share_events": false,
  "share_enriched_documents": true,
  "share_mode": "sanitized",
  "never_share_fields": ["destination.ip"],
  "never_share_if_tags": ["internal"],
  "never_share_classifications": ["confirmed_malicious_infrastructure"],
  "never_share_destination_cidrs": ["10.0.0.0/8"]
}
```

Persists to `config/clients/{client_id}_sharing_policy.json`.

---

## Safelist

### GET /api/v1/safelist?client_id=

**Auth:** Yes — list safelist entries (global + client merge)

### GET /api/v1/safelist/table?client_id=

**Auth:** Yes — flat CIDR table

### POST /api/v1/safelist

**Auth:** Yes

**Request body:**

```json
{
  "client_id": "example-stingar-01",
  "entry": {
    "id": "my-range",
    "cidr": "192.168.1.0/24",
    "actions": { "cap_severity": "LOW", "never_block": true }
  }
}
```

### DELETE /api/v1/safelist/{entry_id}?client_id=

**Auth:** Yes — remove client-owned entry

---

## Scanners

### GET /api/v1/scanners?client_id=

**Auth:** Yes — list merged scanner definitions

### GET /api/v1/scanners/table?client_id=

**Auth:** Yes — flat CIDR table (one row per range)

### GET /api/v1/scanners/inventory

**Auth:** Yes — full CSV inventory metadata + feed status

### POST /api/v1/scanners/refresh?dry_run=false

**Auth:** Yes — refresh vendor feed snapshots

### POST /api/v1/scanners

**Auth:** Yes — add client-owned scanner entry

### DELETE /api/v1/scanners/{scanner_id}?client_id=

**Auth:** Yes — remove client-owned scanner

---

## LLM

### POST /api/v1/llm/investigate

**Auth:** Yes | **Requires:** `global_joined: true` in client policy

Runs Claude agent investigation for an IOC.

**Request body:**

```json
{
  "client_id": "example-stingar-01",
  "ioc": "203.0.113.42",
  "ioc_type": "ip_address"
}
```

**Response:**

```json
{
  "client_id": "example-stingar-01",
  "ioc": "203.0.113.42",
  "ioc_type": "ip_address",
  "analysis": "...natural language report...",
  "tool_calls": [{ "tool": "...", "input": {} }]
}
```

**Errors:** `403` if client is not `global_joined`.

---

## Cache

### GET /api/v1/cache/stats

**Auth:** Yes

Returns intelligence cache backend statistics (backend type, entry counts).

---

## Endpoint summary

| Method | Path | Auth | Typical caller |
|---|---|---|---|
| GET | `/health` | No | Monitoring |
| GET | `/api/v1/cache/stats` | Yes | Ops |
| POST | `/api/v1/enrich/events` | Yes | STINGAR (direct) |
| POST | `/api/v1/enrich/ip` | Yes | Analyst tooling |
| POST | `/api/v1/enrich/ips` | Yes | Analyst tooling |
| POST | `/api/v1/webhooks/stingar` | Yes | STINGAR push |
| POST | `/api/v1/webhooks/stingar/{client_id}` | Yes | STINGAR push |
| POST | `/webhook/stingar` | Secret* | Honeypot → local listener |
| POST | `/api/v1/sync/events` | Yes | Hybrid client / sync worker |
| GET | `/api/v1/sessions` | Yes | Analyst / Kibana |
| POST | `/api/v1/llm/investigate` | Yes | Analyst (joined clients) |
| GET/PUT | `/api/v1/clients/{client_id}/policy` | Yes | Admin |
| GET/POST/DELETE | `/api/v1/safelist*` | Yes | Admin |
| GET/POST/DELETE | `/api/v1/scanners*` | Yes | Admin / CI |

\* Local listener uses optional `X-Webhook-Secret`, not Bearer auth.

## Related docs

- [DEPLOYMENT.md](./DEPLOYMENT.md) — how to start services
- [DATA-MODEL.md](./DATA-MODEL.md) — document schema and query language
- [POLICY-AND-SHARING.md](./POLICY-AND-SHARING.md) — sync and LLM gates
