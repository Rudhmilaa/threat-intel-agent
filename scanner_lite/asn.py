"""ASN resolution and daily batch rollups."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from scanner_lite.endpoints.ip_api import IpApiAdapter
from scanner_lite.endpoints.registry import get_adapter

_asn_cache: dict[str, dict] = {}


def resolve_asn(ip_address: str, existing_signals: Optional[dict] = None) -> dict:
    """Resolve ASN once per IP; prefer signals from cascade, then cache, then APIs."""
    if existing_signals and existing_signals.get("asn"):
        return existing_signals["asn"]

    if ip_address in _asn_cache:
        return _asn_cache[ip_address]

    for name in ("ripestat", "ip_api", "ipinfo"):
        adapter = get_adapter(name)
        if adapter is None:
            continue
        result = adapter.query(ip_address)
        if result.success and result.data.get("asn"):
            asn_data = {
                "number": str(result.data.get("asn")),
                "org": result.data.get("org"),
                "country": result.data.get("country"),
                "source": result.data.get("source", name),
            }
            _asn_cache[ip_address] = asn_data
            return asn_data

    # Final fallback
    fallback = IpApiAdapter().query(ip_address)
    asn_data = {
        "number": str(fallback.data.get("asn")) if fallback.data.get("asn") else "AS0",
        "org": fallback.data.get("org", "unknown"),
        "country": fallback.data.get("country"),
        "source": fallback.data.get("source", "ip-api.com"),
    }
    _asn_cache[ip_address] = asn_data
    return asn_data


def build_asn_batches(enriched_documents: list[dict], batch_date: Optional[str] = None) -> list[dict]:
    """Group enriched documents into daily ASN batch records."""
    date_str = batch_date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    groups: dict[str, dict] = defaultdict(
        lambda: {
            "batch_date": date_str,
            "asn_number": "",
            "org": "",
            "event_count": 0,
            "unique_ips": set(),
            "category_counts": defaultdict(int),
            "frequency_tier_counts": defaultdict(int),
            "behavior_tag_counts": defaultdict(int),
            "api_calls_total": 0,
            "events": [],
        }
    )

    for doc in enriched_documents:
        asn = doc.get("asn") or {}
        asn_number = asn.get("number") or "AS0"
        key = asn_number
        batch = groups[key]
        batch["asn_number"] = asn_number
        batch["org"] = asn.get("org") or batch["org"]
        batch["event_count"] += 1
        source_ip = doc.get("source_ip")
        if source_ip:
            batch["unique_ips"].add(source_ip)
        category = doc.get("outcome_category", "unknown")
        batch["category_counts"][category] += 1
        batch["api_calls_total"] += len(doc.get("api_call_trace", []))

        metadata = doc.get("investigation_metadata") or {}
        freq_tier = metadata.get("frequency_tier")
        if freq_tier:
            batch["frequency_tier_counts"][freq_tier] += 1
        for tag in metadata.get("behavior_tags") or []:
            batch["behavior_tag_counts"][tag] += 1

        batch["events"].append(
            {
                "source_ip": source_ip,
                "outcome_category": category,
                "scanner_tag": doc.get("scanner_tag"),
                "destination_port": doc.get("destination_port"),
                "attack_type": doc.get("attack_type"),
                "frequency_tier": freq_tier,
                "behavior_tags": metadata.get("behavior_tags") or [],
                "priority": metadata.get("priority"),
            }
        )

    results = []
    for batch in groups.values():
        batch["unique_ips"] = sorted(batch["unique_ips"])
        batch["category_counts"] = dict(batch["category_counts"])
        batch["frequency_tier_counts"] = dict(batch["frequency_tier_counts"])
        batch["behavior_tag_counts"] = dict(batch["behavior_tag_counts"])
        results.append(batch)
    return results


def clear_asn_cache() -> None:
    _asn_cache.clear()
