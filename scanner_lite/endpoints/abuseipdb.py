"""AbuseIPDB check — free tier ~1000/day."""

from __future__ import annotations

from threat_intel.lookups import lookup_ip_reputation, lookup_ip_reputation_abuseipdb

from scanner_lite.endpoints.base import EndpointResult


class AbuseIpdbAdapter:
    name = "abuseipdb"
    cost_per_call = 0.001

    def query(self, ip_address: str) -> EndpointResult:
        result = lookup_ip_reputation_abuseipdb(ip_address)
        if "error" in result:
            result = lookup_ip_reputation(ip_address)
            result["source"] = "AbuseIPDB-mock"
        return EndpointResult(
            endpoint=self.name,
            cost=self.cost_per_call if "error" not in result else 0.0,
            success="error" not in result or result.get("abuse_confidence_score") is not None,
            data=result,
            error=result.get("error"),
        )
