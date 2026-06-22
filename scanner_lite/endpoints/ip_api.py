"""ip-api.com geo + ASN lookup — free non-commercial tier."""

from __future__ import annotations

import requests

from scanner_lite.endpoints.base import EndpointResult


class IpApiAdapter:
    name = "ip_api"
    cost_per_call = 0.0

    def query(self, ip_address: str) -> EndpointResult:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,isp,org,as,query"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            payload = response.json()
            if payload.get("status") != "success":
                return EndpointResult(
                    endpoint=self.name,
                    cost=self.cost_per_call,
                    success=False,
                    data=payload,
                    error=payload.get("message", "lookup failed"),
                )
            asn_raw = payload.get("as", "")
            asn_number = asn_raw.split()[0] if asn_raw else None
            return EndpointResult(
                endpoint=self.name,
                cost=self.cost_per_call,
                success=True,
                data={
                    "asn": asn_number,
                    "org": payload.get("org") or payload.get("isp"),
                    "country": payload.get("country"),
                    "source": "ip-api.com",
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
