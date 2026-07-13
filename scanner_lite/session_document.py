"""Map scanner-lite enrichment documents to stingar-enriched session records."""

from __future__ import annotations

from typing import Any, Optional

OUTCOME_SEVERITY = {
    "malicious": "HIGH",
    "suspicious": "MEDIUM",
    "benign": "LOW",
    "unknown": "INFORMATIONAL",
}


def _raw_event(event: Optional[dict]) -> dict:
    if not event:
        return {}
    return event.get("original") or event


def _taxonomy_tags(enriched: dict, meta: dict) -> list[str]:
    tags: list[str] = []
    outcome = enriched.get("outcome_category", "unknown")
    tags.append(f"outcome:{outcome}")

    for behavior in meta.get("behavior_tags") or []:
        tags.append(f"behavior:{behavior}")

    scanner_tag = enriched.get("scanner_tag") or {}
    if scanner_tag.get("scanner_id"):
        tags.append(f"scanner:{scanner_tag['scanner_id']}")
    elif scanner_tag.get("vendor"):
        tags.append(f"scanner:{scanner_tag['vendor']}")

    attribution = meta.get("scanner_attribution")
    if attribution and attribution != "none":
        tags.append(f"attribution:{attribution}")

    freq = meta.get("frequency_tier")
    if freq and freq != "normal":
        tags.append(f"frequency:{freq}")

    return sorted(set(tags))


def _hp_data_from_sources(raw: dict, event: Optional[dict]) -> dict[str, Any]:
    for source in (event, raw):
        if not source:
            continue
        hp = source.get("hpData") or source.get("hp_data")
        if isinstance(hp, dict):
            return hp
    return {}


def _existing_enrichment(hp_data: dict[str, Any]) -> dict[str, Any]:
    enc = hp_data.get("enrichment")
    return dict(enc) if isinstance(enc, dict) else {}


def _lift_c2_engine_fields(hp_data: dict[str, Any], existing: dict[str, Any]) -> dict[str, Any]:
    """Promote c2-engine hp_data fields into enrichment when the annotator stamp is absent."""
    merged = dict(existing)

    if not merged.get("c2s") and not merged.get("c2"):
        c2_hosts = hp_data.get("iocs_c2_hosts")
        if isinstance(c2_hosts, list) and c2_hosts:
            merged["c2s"] = [
                {"ip": host, "stage": "mentioned_in_shell"}
                for host in c2_hosts
                if host
            ]

    payloads = merged.get("payloads")
    has_payloads = bool(
        payloads
        and (isinstance(payloads, list) and payloads or isinstance(payloads, dict) and payloads.get("sha256"))
    )
    if not has_payloads:
        refs = hp_data.get("payload_refs")
        if isinstance(refs, list):
            lifted = []
            for ref in refs:
                if not isinstance(ref, dict) or not ref.get("sha256"):
                    continue
                entry: dict[str, Any] = {"sha256": ref["sha256"]}
                for key in ("family", "kind", "status", "attempted_url"):
                    if ref.get(key):
                        entry[key] = ref[key]
                lifted.append(entry)
            if lifted:
                merged["payloads"] = lifted

    if not merged.get("playbook") and not merged.get("playbook_hash"):
        playbook_hash = hp_data.get("playbook_hash")
        playbook_canonical = hp_data.get("playbook_canonical")
        if playbook_hash or playbook_canonical:
            if playbook_hash:
                merged["playbook_hash"] = playbook_hash
            merged["playbook"] = {
                **({"exact_key": playbook_hash} if playbook_hash else {}),
                **({"canonical": playbook_canonical} if playbook_canonical else {}),
            }

    return merged


def _merge_upstream_enrichment(
    hp_data: dict[str, Any],
    raw: dict,
    event: Optional[dict],
) -> dict[str, Any]:
    existing = _lift_c2_engine_fields(hp_data, _existing_enrichment(hp_data))

    c2_host = raw.get("c2_host") or (event or {}).get("c2_host")
    if c2_host and not existing.get("c2s") and not existing.get("c2"):
        hosts = c2_host if isinstance(c2_host, list) else [c2_host]
        existing["c2s"] = [
            {"ip": host, "stage": "mentioned_in_shell"}
            for host in hosts
            if host
        ]

    return existing


def _build_enrichment_block(
    scanner_lite_block: dict[str, Any],
    upstream: dict[str, Any],
    *,
    severity: str,
    taxonomy_tags: list[str],
    behavior_tags: list[str],
) -> dict[str, Any]:
    block: dict[str, Any] = {
        "version": upstream.get("version") or "scanner-lite-1",
        "effective_severity": upstream.get("effective_severity") or severity,
        "effective_signals": upstream.get("effective_signals")
        or sorted(set(taxonomy_tags + behavior_tags)),
        "scanner_lite": scanner_lite_block,
    }
    for key in (
        "c2",
        "c2s",
        "payloads",
        "playbook",
        "playbook_hash",
        "signals",
        "status",
        "norm_version",
        "enriched_at",
    ):
        value = upstream.get(key)
        if value not in (None, {}, []):
            block[key] = value
    return block


def build_outcome_summary(
    enriched: dict,
    meta: dict,
    scanner_tag: Optional[dict],
) -> dict[str, Any]:
    """Compact hover/drilldown payload for Attack Analysis session rows."""
    summary: dict[str, Any] = {
        "confidence": enriched.get("outcome_confidence"),
        "priority": meta.get("priority"),
        "classification": meta.get("investigation_classification"),
        "scanner_attribution": meta.get("scanner_attribution"),
        "frequency_tier": meta.get("frequency_tier"),
        "events_today": meta.get("events_today"),
        "behavior_tags": list(meta.get("behavior_tags") or []),
        "reasons": list(enriched.get("outcome_reasons") or []),
    }
    if scanner_tag:
        summary["scanner_vendor"] = scanner_tag.get("vendor")
        summary["scanner_id"] = scanner_tag.get("scanner_id")
        summary["matched_cidr"] = scanner_tag.get("matched_cidr")
    if meta.get("scanner_inventory_version") is not None:
        summary["inventory_version"] = meta["scanner_inventory_version"]
    return summary


def to_stingar_session(
    enriched: dict,
    event: Optional[dict] = None,
    *,
    client_id: str = "scanner-lite",
) -> dict:
    """Convert a scanner-lite enrichment doc into a stingar-enriched session document."""
    meta = enriched.get("investigation_metadata") or {}
    outcome = enriched.get("outcome_category", "unknown")
    severity = OUTCOME_SEVERITY.get(outcome, "INFORMATIONAL")
    raw = _raw_event(event)
    hp_data = _hp_data_from_sources(raw, event)
    upstream_enrichment = _merge_upstream_enrichment(hp_data, raw, event)
    behavior_tags = meta.get("behavior_tags") or []
    scanner_tag = enriched.get("scanner_tag")
    taxonomy_tags = _taxonomy_tags(enriched, meta)

    source_ip = enriched.get("source_ip")
    source_port = raw.get("srcPort") or raw.get("source_port") or event.get("source_port") if event else None
    session_id = raw.get("session_id") or raw.get("sessionId")

    source: dict[str, Any] = {"ip": source_ip}
    if source_port is not None:
        source["port"] = source_port

    destination: dict[str, Any] = {}
    if enriched.get("destination_ip"):
        destination["ip"] = enriched.get("destination_ip")
    if enriched.get("destination_port") is not None:
        destination["port"] = enriched.get("destination_port")

    asn = enriched.get("asn") or {}
    if asn.get("country"):
        source["geo"] = {"country_code": asn["country"]}

    trace = enriched.get("api_call_trace") or []
    scanner_lite_block: dict[str, Any] = {
        "outcome_category": outcome,
        "outcome_confidence": enriched.get("outcome_confidence"),
        "scanner_attribution": meta.get("scanner_attribution"),
        "frequency_tier": meta.get("frequency_tier"),
        "events_today": meta.get("events_today"),
        "events_in_batch": meta.get("events_in_batch"),
        "behavior_tags": behavior_tags,
        "api_calls": len(trace),
    }
    if scanner_tag:
        scanner_lite_block["scanner_vendor"] = scanner_tag.get("vendor")
        scanner_lite_block["scanner_id"] = scanner_tag.get("scanner_id")
        scanner_lite_block["matched_cidr"] = scanner_tag.get("matched_cidr")

    if meta.get("scanner_inventory_version") is not None:
        scanner_lite_block["inventory_version"] = meta["scanner_inventory_version"]
    if meta.get("scanner_inventory_refreshed_at"):
        scanner_lite_block["inventory_refreshed_at"] = meta["scanner_inventory_refreshed_at"]

    ts = enriched.get("@timestamp")
    honeypot_type = enriched.get("honeypot_type") or raw.get("app") or (event or {}).get("honeypot_type")
    protocol = enriched.get("protocol") or raw.get("protocol") or (event or {}).get("protocol")

    doc = {
        "@timestamp": ts,
        "start_time": ts,
        "app": honeypot_type,
        "protocol": protocol,
        "src_ip": source_ip,
        "outcome_category": outcome,
        "outcome_summary": build_outcome_summary(enriched, meta, scanner_tag),
        "source": source,
        "destination": destination,
        "network": {
            "protocol": enriched.get("protocol"),
            "transport": raw.get("transport") or (event or {}).get("transport") or "tcp",
        },
        "stingar": {
            "sensor_id": enriched.get("sensor_id"),
            "honeypot_type": enriched.get("honeypot_type"),
            "attack_type": enriched.get("attack_type"),
        },
        "threat": {
            "indicator": {"ip": source_ip, "type": "ip_address"},
            "severity": severity,
            "confidence_score": enriched.get("outcome_confidence"),
            "risk_factors": list(enriched.get("outcome_reasons") or []),
        },
        "investigation": {
            "classification": meta.get("investigation_classification"),
            "category": outcome,
            "priority": meta.get("priority"),
            "reasons": list(enriched.get("outcome_reasons") or []),
        },
        "taxonomy": {"tags": taxonomy_tags},
        "hp_data": {
            "enrichment": _build_enrichment_block(
                scanner_lite_block,
                upstream_enrichment,
                severity=severity,
                taxonomy_tags=taxonomy_tags,
                behavior_tags=behavior_tags,
            ),
            **{
                key: hp_data[key]
                for key in ("playbook_hash", "playbook_canonical", "payload_refs", "iocs_c2_hosts")
                if key in hp_data
            },
        },
        "elastic_metadata": {
            "document_type": "stingar_enriched_honeypot_event",
            "pipeline": "scanner-enrichment-lite",
            "client_id": client_id,
            "version": "1.0",
        },
        "event": {
            "source": "stingar_honeypot",
            "type": "honeypot_attack",
            "original": raw or event,
        },
    }
    if session_id:
        sid = str(session_id)
        doc["session_id"] = sid
        doc["stingar"]["session_id"] = sid
    return doc
