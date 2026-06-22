"""Base types for enrichment endpoint adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol


@dataclass
class EndpointResult:
    endpoint: str
    cost: float
    success: bool
    data: dict = field(default_factory=dict)
    error: Optional[str] = None

    def to_trace_entry(self) -> dict:
        entry = {
            "endpoint": self.endpoint,
            "cost": self.cost,
            "success": self.success,
        }
        if self.error:
            entry["error"] = self.error
        if self.data:
            entry["result"] = _summarize_data(self.data)
        return entry


def _summarize_data(data: dict) -> dict:
    """Keep trace payloads small."""
    summary = {}
    for key in (
        "is_known_scanner",
        "classification",
        "abuse_confidence_score",
        "asn",
        "org",
        "country",
        "noise_classification",
        "pulse_count",
    ):
        if key in data:
            summary[key] = data[key]
    if not summary and data:
        summary["keys"] = list(data.keys())[:8]
    return summary


class EndpointAdapter(Protocol):
    name: str
    cost_per_call: float

    def query(self, ip_address: str) -> EndpointResult: ...
