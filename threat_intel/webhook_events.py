"""Normalize STINGAR/Cowrie webhook payloads into the central event schema."""

from __future__ import annotations

from typing import Any, Optional


def _pick(data: dict, *keys: str) -> Any:
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    return None


def normalize_event(raw_event: dict, default_sensor_id: Optional[str] = None) -> dict:
    """
    Accept native STINGAR events or common Cowrie-style webhook payloads.
    """
    source_ip = _pick(
        raw_event,
        "source_ip",
        "src_ip",
        "sourceIp",
        "srcIp",
        "peer_ip",
        "remote_ip",
    )
    destination_ip = _pick(
        raw_event,
        "destination_ip",
        "dst_ip",
        "destinationIp",
        "dstIp",
        "sensor_ip",
        "local_ip",
    )
    destination_port = _pick(
        raw_event,
        "destination_port",
        "dst_port",
        "destinationPort",
        "dstPort",
        "dest_port",
        "port",
    )
    source_port = _pick(raw_event, "source_port", "src_port", "sourcePort", "srcPort")
    protocol = _pick(raw_event, "protocol", "app_protocol", "service")
    transport = _pick(raw_event, "transport", "transport_protocol") or "tcp"
    sensor_id = _pick(raw_event, "sensor_id", "sensorId", "hostname") or default_sensor_id
    honeypot_type = _pick(raw_event, "honeypot_type", "honeypotType", "sensor_type") or "unknown"
    attack_type = _pick(
        raw_event,
        "attack_type",
        "attackType",
        "event_type",
        "eventid",
        "action",
    ) or "unknown_attack"

    return {
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
        "transport": transport,
        "sensor_id": sensor_id,
        "honeypot_type": honeypot_type,
        "attack_type": attack_type,
        "original": raw_event,
    }


def extract_events(payload: dict | list, default_sensor_id: Optional[str] = None) -> list[dict]:
    if isinstance(payload, list):
        raw_events = payload
    elif isinstance(payload, dict):
        if "events" in payload and isinstance(payload["events"], list):
            raw_events = payload["events"]
        elif "event" in payload and isinstance(payload["event"], dict):
            raw_events = [payload["event"]]
        else:
            raw_events = [payload]
    else:
        raw_events = []

    return [normalize_event(event, default_sensor_id=default_sensor_id) for event in raw_events]
