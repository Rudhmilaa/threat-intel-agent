"""AlienVault OTX IP reputation — free."""

from __future__ import annotations

import requests

from scanner_lite.endpoints.base import EndpointResult


class OtxAdapter:
    name = "otx"
    cost_per_call = 0.0

    def query(self, ip_address: str) -> EndpointResult:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            payload = response.json()
            return EndpointResult(
                endpoint=self.name,
                cost=self.cost_per_call,
                success=True,
                data={
                    "pulse_count": payload.get("pulse_info", {}).get("count", 0),
                    "reputation": payload.get("reputation", 0),
                    "country": payload.get("country_name"),
                    "asn": payload.get("asn"),
                    "source": "AlienVault OTX",
                },
            )
        except Exception as error:
            return EndpointResult(
                endpoint=self.name,
                cost=self.cost_per_call,
                success=False,
                data={},
                error=str(error),
            )
