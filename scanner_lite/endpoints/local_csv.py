"""Local CSV/CIDR scanner registry lookup — always free."""

from __future__ import annotations

from threat_intel.scanners import classify_known_scanner

from scanner_lite.endpoints.base import EndpointResult


class LocalCsvAdapter:
    name = "local_csv"
    cost_per_call = 0.0

    def query(self, ip_address: str) -> EndpointResult:
        result = classify_known_scanner(ip_address)
        return EndpointResult(
            endpoint=self.name,
            cost=self.cost_per_call,
            success=True,
            data=result,
        )
