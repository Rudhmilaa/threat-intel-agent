"""Session query language — tokenizer and ES bool-query builder (DATA-AND-VIEWS §8d subset)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Optional

# Public alias → indexed field path (never expose raw ES paths in API)
FIELD_ALIASES = {
    "src_ip": "src_ip",
    "c2": "hp_data.enrichment.c2.value",
    "c2_stage": "hp_data.enrichment.c2.stage",
    "payload": "hp_data.enrichment.payloads.sha256",
    "sha256": "hp_data.enrichment.payloads.sha256",
    "family": "campaign.name",
    "playbook": "hp_data.enrichment.playbook.name",
    "signal": "effective_signals",
    "severity": "effective_severity",
    "country": "source.geo.country_code",
    "location": "source.geo.country_code",
    "honeypot": "stingar.honeypot_type",
    "protocol": "network.protocol",
    "sensor": "stingar.sensor_id",
    "verdict": "investigation.classification",
    "client_id": "elastic_metadata.client_id",
}

SEVERITY_RANK = {
    "INFO": 0,
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(/(\d{1,2}))?$")


@dataclass
class QueryTerm:
    field: str
    value: str
    negated: bool = False
    exists_only: bool = False
    range_op: Optional[str] = None


def _tokenize(query: str) -> list[QueryTerm]:
    terms: list[QueryTerm] = []
    if not query or not query.strip():
        return terms

    for raw in query.strip().split():
        negated = raw.startswith("-")
        token = raw[1:] if negated else raw

        if ":" not in token:
            terms.append(_route_bare_token(token, negated))
            continue

        field, _, value = token.partition(":")
        field = field.strip().lower()
        value = value.strip().strip('"')

        if field not in FIELD_ALIASES:
            known = ", ".join(sorted(FIELD_ALIASES))
            raise ValueError(f"Unknown query field '{field}'. Known fields: {known}")

        if value in ("", "*"):
            terms.append(QueryTerm(field=field, value="", exists_only=True, negated=negated))
            continue

        range_op = None
        for op in (">=", "<=", ">", "<"):
            if value.startswith(op):
                range_op = op
                value = value[len(op) :]
                break

        terms.append(
            QueryTerm(field=field, value=value, negated=negated, range_op=range_op)
        )

    return terms


def _route_bare_token(token: str, negated: bool) -> QueryTerm:
    if SHA256_RE.match(token):
        return QueryTerm(field="sha256", value=token.lower(), negated=negated)
    if IP_RE.match(token):
        return QueryTerm(field="src_ip", value=token, negated=negated)
    return QueryTerm(field="_text", value=token, negated=negated)


def parse_session_query(query: str) -> list[QueryTerm]:
    return _tokenize(query)


def _severity_range_clause(op: str, value: str) -> dict:
    threshold = SEVERITY_RANK.get(value.upper())
    if threshold is None:
        return {"term": {"effective_severity": value.upper()}}

    if op == ">=":
        allowed = [k for k, v in SEVERITY_RANK.items() if v >= threshold]
    elif op == ">":
        allowed = [k for k, v in SEVERITY_RANK.items() if v > threshold]
    elif op == "<=":
        allowed = [k for k, v in SEVERITY_RANK.items() if v <= threshold]
    elif op == "<":
        allowed = [k for k, v in SEVERITY_RANK.items() if v < threshold]
    else:
        allowed = [value.upper()]

    return {"terms": {"effective_severity": sorted(set(allowed))}}


def _term_clause(field_alias: str, term: QueryTerm) -> dict:
    es_field = FIELD_ALIASES.get(field_alias, field_alias)

    if term.exists_only:
        return {"exists": {"field": es_field}}

    if field_alias == "severity" and term.range_op:
        return _severity_range_clause(term.range_op, term.value)

    if field_alias == "src_ip" and "/" in term.value:
        return {"term": {es_field: term.value.split("/")[0]}}

    if field_alias in {"src_ip", "c2"}:
        return {"term": {es_field: term.value}}

    if term.value.endswith("*"):
        return {"wildcard": {es_field: term.value}}

    return {"term": {es_field: term.value}}


def session_query_to_es(
    query: str,
    *,
    client_id: Optional[str] = None,
    hours: Optional[int] = 24,
) -> dict:
    """Build a single-index bool query for stingar-enriched-*."""
    must: list[dict] = []
    must_not: list[dict] = []
    filter_clauses: list[dict] = []

    if client_id:
        filter_clauses.append({"term": {"elastic_metadata.client_id": client_id}})

    if hours is not None and hours > 0:
        filter_clauses.append({"range": {"@timestamp": {"gte": f"now-{hours}h"}}})

    for term in parse_session_query(query):
        if term.field == "_text":
            clause = {
                "multi_match": {
                    "query": term.value,
                    "fields": [
                        "investigation.classification",
                        "campaign.name",
                        "stingar.attack_type",
                        "effective_signals",
                    ],
                }
            }
        else:
            clause = _term_clause(term.field, term)

        if term.negated:
            must_not.append(clause)
        else:
            must.append(clause)

    body: dict[str, Any] = {
        "query": {
            "bool": {
                "must": must,
                "must_not": must_not,
                "filter": filter_clauses,
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}],
    }
    return body
