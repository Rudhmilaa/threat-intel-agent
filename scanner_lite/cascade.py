"""Ranked API cascade with stop conditions and api_call_trace."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from scanner_lite.classifier import classify_outcome
from scanner_lite.endpoints.base import EndpointResult
from scanner_lite.endpoints.registry import ADAPTERS, DEFAULT_CASCADE, get_adapter

RANKING_PATH = Path(__file__).resolve().parent / "eval" / "ranking.json"

STOP_CATEGORIES = {"benign", "malicious"}
CONFIDENCE_THRESHOLD = 0.8
MAX_PAID_CALLS = 3


def load_cascade_order() -> list[str]:
    if RANKING_PATH.exists():
        payload = json.loads(RANKING_PATH.read_text(encoding="utf-8"))
        ranked = payload.get("cascade_order")
        if ranked:
            return [name for name in ranked if name in ADAPTERS and name != "local_csv"]
    return list(DEFAULT_CASCADE)


def merge_signals(signals: dict[str, Any], endpoint_name: str, data: dict) -> None:
    if endpoint_name == "local_csv":
        signals["scanner_tag"] = data
    elif endpoint_name == "greynoise":
        signals["greynoise"] = data
    elif endpoint_name == "abuseipdb":
        signals["abuseipdb"] = data
    elif endpoint_name == "otx":
        signals["otx"] = data
    elif endpoint_name in ("ripestat", "ip_api", "ipinfo"):
        if data.get("asn") or data.get("org"):
            signals.setdefault("asn", {})
            signals["asn"].update({k: data.get(k) for k in ("asn", "org", "country") if data.get(k)})
    elif endpoint_name == "shodan_internetdb":
        signals["shodan"] = data


def should_stop(outcome: dict) -> bool:
    category = outcome.get("outcome_category")
    confidence = outcome.get("confidence", 0)
    return category in STOP_CATEGORIES and confidence >= CONFIDENCE_THRESHOLD


def run_cascade(ip_address: str, *, skip_paid: bool = False) -> dict:
    """
    Run local_csv first, then up to MAX_PAID_CALLS ranked endpoints.
    Returns signals, api_call_trace, and outcome.
    """
    signals: dict[str, Any] = {}
    trace: list[dict] = []
    paid_calls = 0

    csv_adapter = get_adapter("local_csv")
    csv_result = csv_adapter.query(ip_address)
    trace.append(csv_result.to_trace_entry())
    merge_signals(signals, "local_csv", csv_result.data)

    outcome = classify_outcome(signals)
    if should_stop(outcome):
        return {"signals": signals, "api_call_trace": trace, "outcome": outcome}

    if skip_paid:
        return {"signals": signals, "api_call_trace": trace, "outcome": outcome}

    for endpoint_name in load_cascade_order():
        if paid_calls >= MAX_PAID_CALLS:
            break
        adapter = get_adapter(endpoint_name)
        if adapter is None:
            continue
        if adapter.cost_per_call > 0:
            paid_calls += 1
        result: EndpointResult = adapter.query(ip_address)
        trace.append(result.to_trace_entry())
        if result.success and result.data:
            merge_signals(signals, endpoint_name, result.data)
        outcome = classify_outcome(signals)
        if should_stop(outcome):
            break

    return {"signals": signals, "api_call_trace": trace, "outcome": outcome}
