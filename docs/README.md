# Documentation

Technical documentation for **threat-intel-agent** — a hybrid local/global STINGAR enrichment service.

## Reading order (new teammates)

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
| [ARCHITECTURE.md](./ARCHITECTURE.md) | System design, deployment topologies, module map |
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
| [CODE_REVIEW.md](./CODE_REVIEW.md) | Internal engineering review; includes c2-engine comparison |
| [C2_ENGINE_INTEGRATION.md](./C2_ENGINE_INTEGRATION.md) | Porting modules into c2-engine inline engine |

For a standalone view of this repo, start with **ARCHITECTURE.md** — not CODE_REVIEW.md.

## Quick links

- Project entry point: [../README.md](../README.md)
- Run tests: `STINGAR_STORAGE_BACKEND=sqlite python -m unittest discover -s tests`
- Central health: `GET /health`
- Session search: `GET /api/v1/sessions?q=severity:>=high&hours=24`
