"""Normalize Fluentd-forwarded STINGAR honeypot records for enrichment."""

from __future__ import annotations

from typing import Any


def normalize_fluentd_payload(payload: dict | list) -> dict | list:
    """
    Accept Fluentd out_http JSON shapes and return a webhook-compatible payload.

    Supports:
    - Single event dict (srcIp / hpData / app)
    - ``{ "events": [...] }`` batch wrapper
    - List of events
    - Fluentd wrapper ``{ "record": {...} }`` or ``{ "json": {...} }``
    """
    if isinstance(payload, list):
        return {"events": [_unwrap_record(item) for item in payload if isinstance(item, dict)]}

    if not isinstance(payload, dict):
        return {"events": []}

    if "events" in payload and isinstance(payload["events"], list):
        return {"events": [_unwrap_record(item) for item in payload["events"] if isinstance(item, dict)]}

    if "record" in payload and isinstance(payload["record"], dict):
        return {"events": [_unwrap_record(payload["record"])]}

    if "json" in payload and isinstance(payload["json"], dict):
        inner = payload["json"]
        if "events" in inner:
            return normalize_fluentd_payload(inner)
        return {"events": [_unwrap_record(inner)]}

    return {"events": [_unwrap_record(payload)]}


def _unwrap_record(record: dict) -> dict:
    """Map common Fluentd/STINGAR field aliases onto native event keys."""
    event = dict(record)

    if "srcIp" in event and "src_ip" not in event:
        event.setdefault("src_ip", event["srcIp"])
    if "dstIp" in event and "destination_ip" not in event:
        event.setdefault("destination_ip", event["dstIp"])
    if "dstPort" in event and "destination_port" not in event:
        event.setdefault("destination_port", event["dstPort"])
    if "app" in event and "honeypot_type" not in event:
        event.setdefault("honeypot_type", event["app"])

    hp = event.get("hpData") or event.get("hp_data")
    if hp and "hpData" not in event:
        event["hpData"] = hp

    return event
