# Policy and Sharing

Safelist rules, sharing policy, sync behavior, and LLM access control.

## Deployment modes

Configured via `STINGAR_DEPLOYMENT_MODE` env var or `config/clients/{client_id}_sharing_policy.json`:

| Mode | Local enrich | Sync to central | LLM gateway |
|---|---|---|---|
| `hybrid` (default) | Always | When online + policy allows | No (unless `global_joined: true`) |
| `local_only` | Always | Never | No |
| `global_joined` | Always | When online + policy allows | Yes |

```json
{
  "client_id": "example-stingar-01",
  "deployment_mode": "hybrid",
  "global_joined": false,
  "share_enriched_documents": true,
  "share_mode": "sanitized"
}
```

## Safelist vs scanner registry

These answer different questions:

| Registry | Question | Effect |
|---|---|---|
| **Scanner registry** | Who is this IP? | Sets investigation classification to `known_scanner` |
| **Safelist** | Should we never block/escalate? | Caps severity, adds `policy:never_block` tags |

### Safelist config

- Global: `config/safelist/default_safelist.json`
- Per-client: `config/clients/{client_id}_safelist.json`

Each entry defines a CIDR range and actions:

```json
{
  "id": "duke-resnet",
  "provider": "Duke University",
  "cidr": "152.3.0.0/16",
  "direction": "inbound",
  "actions": {
    "cap_severity": "LOW",
    "never_block": true,
    "never_escalate": true
  }
}
```

Applied by `SafelistRegistry.match_ip()` in `threat_intel/safelist.py`. When matched:

- Severity capped via `SafelistRegistry.cap_severity()`
- Tags added: `policy:safelisted`, optionally `policy:never_block`, `policy:never_escalate`
- Investigation block gets `safelist` metadata

## Sharing policy

Default policy in `threat_intel/sharing_policy.py`:

| Setting | Default | Purpose |
|---|---|---|
| `share_events` | `false` | Raw events not shared (enriched docs only) |
| `share_enriched_documents` | `true` | Allow sync of enriched documents |
| `share_mode` | `sanitized` | Strip sensitive fields before sync |
| `never_share_fields` | `destination.ip`, `event.original`, `stingar.sensor_id` | Fields removed on sync |
| `never_share_if_tags` | `internal`, `student_network`, `policy:share_blocked` | Block sync if tag present |
| `never_share_classifications` | `confirmed_malicious_infrastructure` | Block by investigation class |
| `never_share_destination_cidrs` | RFC1918 ranges | Block if destination is private |

Example client override: [`config/clients/example-stingar-01_sharing_policy.json`](../config/clients/example-stingar-01_sharing_policy.json)

## Shareability evaluation

`threat_intel/policy_engine.evaluate_shareability(document, client_id)` returns:

```json
{
  "allowed": true,
  "reason": "ok",
  "sanitized_document": { "...stripped fields..." }
}
```

Rejection reasons include:

- `share_enriched_documents` disabled
- Classification in `never_share_classifications`
- Tag in `never_share_if_tags`
- Destination IP in blocked CIDR (checked after sanitization)
- Missing required fields after sanitization

## Sync flow: local to central

### What HybridEnrichmentClient sends

After local enrichment, the client evaluates each document:

```python
# stingar/client.py
for document in local_result["enriched_documents"]:
    decision = evaluate_shareability(document, self.client_id)
    if decision["allowed"]:
        shareable_docs.append(decision["sanitized_document"])
```

Sync payload (`POST /api/v1/sync/events`):

```json
{
  "client_id": "example-stingar-01",
  "sensor_id": "stingar-duke-sensor-01",
  "enriched_documents": ["...sanitized..."],
  "batch_summary": {},
  "incident_clusters": [],
  "prioritized_incidents": [],
  "enrichment_stats": {},
  "enrichment_source": "local"
}
```

Skipped when:

- `deployment_mode == local_only`
- `central_url` not configured
- All documents blocked by policy

### What central re-checks

Central does not trust the client's policy evaluation alone. `sync_events` in `central/server.py`:

1. Re-runs `evaluate_shareability()` on every document
2. Rejects documents that fail central policy
3. Returns **403** if all documents rejected
4. Merges accepted summaries into intelligence cache
5. Indexes accepted documents to Elasticsearch

## Sanitization

`sanitize_document(document, policy)` in `policy_engine.py`:

- Deep-copies the document
- Deletes each field in `never_share_fields` (dotted paths like `destination.ip`)
- Adds `policy:share_blocked` tag when classification is blocked

Sanitization runs **before** ES index writes on both local and central paths.

## LLM gateway gate

LLM investigations are **central-only**. `central/llm_gateway.py` checks:

1. `STINGAR_ENABLE_LLM` is not `true` on the calling node (guard against local LLM use)
2. `can_use_llm(client_id)` returns true — requires `global_joined: true` in sharing policy

```bash
curl -X POST http://127.0.0.1:8080/api/v1/llm/investigate \
  -H "Authorization: Bearer $CENTRAL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"example-stingar-01","ioc":"203.0.113.42","ioc_type":"ip_address"}'
```

Returns 403 if `global_joined` is false.

## Offline sync queue

When central is unreachable, `HybridEnrichmentClient` queues sanitized payloads:

- Storage: `data/sync_queue.db` (configurable via `STINGAR_SYNC_QUEUE_PATH`)
- Drain: `python -m stingar.sync_worker`
- Retries failed items with error logging

The queue holds **already-sanitized** payloads. Central still re-validates on receive.

## Policy API

Manage policy at runtime:

```bash
# Read current policy + safelist summary
curl -H "Authorization: Bearer $CENTRAL_API_KEY" \
  http://127.0.0.1:8080/api/v1/clients/example-stingar-01/policy

# Update deployment mode or sharing rules
curl -X PUT http://127.0.0.1:8080/api/v1/clients/example-stingar-01/policy \
  -H "Authorization: Bearer $CENTRAL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"global_joined": true}'
```

Updates persist to `config/clients/{client_id}_sharing_policy.json`.

## Taxonomy policy tags

Documents and clusters may carry policy-related taxonomy tags:

| Tag | Meaning |
|---|---|
| `policy:safelisted` | Source IP matched safelist |
| `policy:never_block` | Safelist action: do not block |
| `policy:never_escalate` | Safelist action: do not escalate |
| `policy:share_blocked` | Document blocked from sync |

## Related docs

- [ARCHITECTURE.md](./ARCHITECTURE.md) — trust boundaries
- [API-REFERENCE.md](./API-REFERENCE.md) — policy and safelist endpoints
- [DEPLOYMENT.md](./DEPLOYMENT.md) — env vars for deployment modes
