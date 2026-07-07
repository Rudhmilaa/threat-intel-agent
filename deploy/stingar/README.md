# STINGAR v2.3 deployment with scanner-lite enrichment sidecar.
#
# Layout:
#   base/              Stock STINGAR compose + fluentd/nginx (unmodified reference)
#   fluentd.conf       Patched: stingar.events.* -> scanner-lite HTTP -> ES
#   docker-compose.yml Full stack (stock + scanner-lite + patched fluentd + UI build)
#   scanner-lite.overlay.yml  Drop-in overlay for existing STINGAR installs
#
# Vendored from origin/c2-engine:c2-engine/deploy/ (Duke GitLab, tag v2.3).
# UI/API source extracted from 4warned/*:v2.3 images into ../../vendor/.

## Quick start (full stack)

See **[docs/DEMO-DEPLOY.md](../../docs/DEMO-DEPLOY.md)** for collaborator step-by-step instructions.

One command from repo root:

```bash
./scripts/deploy-stingar-demo.sh
```

Manual steps:

```bash
cd deploy/stingar
cp stingar.env.demo stingar.env
mkdir -p storage/db certs

docker compose up -d
../../scripts/deploy-stingar-integration.sh templates
../../scripts/deploy-stingar-integration.sh seed-redis
../../scripts/deploy-stingar-integration.sh smoke
```

Requires ~5GB free disk for Elasticsearch + image pulls.

**Automated demo:** from repo root run `./scripts/deploy-stingar-demo.sh` — see [docs/DEMO-DEPLOY.md](../../docs/DEMO-DEPLOY.md).

## Overlay on existing STINGAR

From your STINGAR deployment directory:

```bash
cp /path/to/threat-intel-agent-lite/deploy/stingar/fluentd.conf ./fluentd.conf

docker compose \
  -f docker-compose.yml \
  -f /path/to/threat-intel-agent-lite/deploy/stingar/scanner-lite.overlay.yml \
  up -d scanner-lite fluentd
```

## Architecture

```
honeypot -> fluent-bit -> fluentd (stingar.events.*)
                              |
                              +-> HTTP POST scanner-lite:8091/ingest/fluentd
                              |         |
                              |         v
                              |    elasticsearch (stingar-* session docs)
                              +-> CIF / file / syslog (unchanged)
```

Fluentd no longer writes `stingar.events.*` directly to Elasticsearch.
scanner-lite enriches and upserts session documents with `outcome_category`.

## Refresh UI/API vendor trees

```bash
./scripts/extract-stingar-images.sh
```

Uses `crane` when available (no Docker daemon required). Re-apply UI patches after re-extract (outcome column, C2/PAYLOAD/PLAYBOOK helpers).

## Deploy patched Attack Analysis UI (OUTCOME column)

From repo root on the STINGAR VM:

```bash
./scripts/deploy-stingar-ui-vm.sh
```

Or manually:

```bash
cd deploy/stingar
docker compose build --build-arg VERSION=v2.3 stingarui
docker compose up -d stingarui
```

Hard-refresh the browser. Attack Analysis → Overview shows **OUTCOME** (between Location and C2) with hover popover for scanner/metadata.

## Rollback

Restore stock fluentd routing by mounting `base/fluentd.conf` instead of `fluentd.conf`.
