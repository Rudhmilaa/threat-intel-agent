"""RIPEstat ASN lookup — free."""

from __future__ import annotations

import requests

from scanner_lite.endpoints.base import EndpointResult


class RipestatAdapter:
    name = "ripestat"
    cost_per_call = 0.0

    def query(self, ip_address: str) -> EndpointResult:
        url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={ip_address}"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            payload = response.json()
            data_block = payload.get("data", {})
            asns = data_block.get("asns", [])
            asn_info = asns[0] if asns else {}
            return EndpointResult(
                endpoint=self.name,
                cost=self.cost_per_call,
                success=True,
                data={
                    "asn": asn_info.get("asn"),
                    "org": asn_info.get("holder"),
                    "prefix": data_block.get("resource"),
                    "source": "RIPEstat",
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
