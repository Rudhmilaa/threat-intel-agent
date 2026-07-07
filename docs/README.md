# Documentation

Technical documentation for **threat-intel-agent** — a hybrid local/global STINGAR enrichment service.

## Reading order (new teammates)

### Scanner enrichment lite (`scanner-enrichment-lite` branch)

1. **[SCANNER-LITE.md](./SCANNER-LITE.md)** — quick start, API, demo IPs
2. **[DEMO-DEPLOY.md](./DEMO-DEPLOY.md)** — **start here for demos** (one-command deploy, full/lite/native paths)
3. **[SCANNER-LITE-DEMO.md](./SCANNER-LITE-DEMO.md)** — end-to-end demo script (curl, session integration, Kibana)
4. **[SCANNER-LITE-ARCHITECTURE.md](./SCANNER-LITE-ARCHITECTURE.md)** — system design, module map, mermaid diagrams
5. **[CODE_REVIEW.md](./CODE_REVIEW.md)** — reviewer checklist and verification script
6. **[API-CASCADE.md](./API-CASCADE.md)** — endpoint eval, ranking, cost model

### Full hybrid platform (`threat-enrich-agent` branch)

1. **[ARCHITECTURE.md](./ARCHITECTURE.md)** — where components run, data flows, trust boundaries
2. **[ENRICHMENT.md](./ENRICHMENT.md)** — how scoring, classification, and clustering work
3. **[DATA-MODEL.md](./DATA-MODEL.md)** — Elasticsearch indices, document schema, query language
4. **[POLICY-AND-SHARING.md](./POLICY-AND-SHARING.md)** — what can leave a STINGAR node
5. **[DEPLOYMENT.md](./DEPLOYMENT.md)** — how to run central, webhook listener, sync worker
6. **[API-REFERENCE.md](./API-REFERENCE.md)** — REST endpoint catalog
7. **[DECISIONS.md](./DECISIONS.md)** — architecture decision log (ADRs)
8. **[ROADMAP.md](./ROADMAP.md)** — open work and known gaps

## Doc index

| Document | Covers |
|---|---|
| [DEMO-DEPLOY.md](./DEMO-DEPLOY.md) | **Collaborator demo deploy** (one script, full/lite/native, troubleshooting) |
| [SCANNER-LITE.md](./SCANNER-LITE.md) | Quick start, API, demo, session integration |
| [SCANNER-LITE-DEMO.md](./SCANNER-LITE-DEMO.md) | Full end-to-end demo walkthrough and copy-paste script |
| [SCANNER-LITE-ARCHITECTURE.md](./SCANNER-LITE-ARCHITECTURE.md) | Scanner-lite system design (mermaid diagrams) |
| [CODE_REVIEW.md](./CODE_REVIEW.md) | Reviewer checklist, test map, demo verification |
| [API-CASCADE.md](./API-CASCADE.md) | 8 endpoints, overlap eval, cascade ranking |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Full hybrid system design, deployment topologies |
| [ENRICHMENT.md](./ENRICHMENT.md) | Pipeline stages, severity vs investigation, scanner Tier-0 |
| [DATA-MODEL.md](./DATA-MODEL.md) | ES indices, enriched documents, config file layout |
| [POLICY-AND-SHARING.md](./POLICY-AND-SHARING.md) | Safelist, sharing policy, sync rules, LLM gate |
| [DEPLOYMENT.md](./DEPLOYMENT.md) | Services, env vars, ES bootstrap, test mode |
| [API-REFERENCE.md](./API-REFERENCE.md) | Auth, endpoints, request/response shapes |
| [DECISIONS.md](./DECISIONS.md) | Repo-specific ADRs |
| [ROADMAP.md](./ROADMAP.md) | Planned work and medium-priority items |

## Cross-repo / review

| Document | Audience |
|---|---|
| [CODE_REVIEW.md](./CODE_REVIEW.md) | Scanner-lite branch review checklist |
| [SCANNER-LITE-ARCHITECTURE.md](./SCANNER-LITE-ARCHITECTURE.md) | Scanner-lite architecture deep dive |
| [C2_ENGINE_INTEGRATION.md](./C2_ENGINE_INTEGRATION.md) | Porting modules into c2-engine inline engine |

For scanner-lite on this branch, start with **SCANNER-LITE.md** then **SCANNER-LITE-ARCHITECTURE.md**. For the full hybrid platform, start with **ARCHITECTURE.md**.

## Quick links

- Project entry point: [../README.md](../README.md)
- Run tests: `STINGAR_STORAGE_BACKEND=sqlite python -m unittest discover -s tests`
- Central health: `GET /health`
- Session search: `GET /api/v1/sessions?q=severity:>=high&hours=24`
