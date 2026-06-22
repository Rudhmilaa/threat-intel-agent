"""ipinfo.io lite — free tier ASN/org enrichment."""

from __future__ import annotations

import os

import requests

from scanner_lite.endpoints.base import EndpointResult


class IpinfoAdapter:
    name = "ipinfo"
    cost_per_call = 0.0

    def query(self, ip_address: str) -> EndpointResult:
        token = os.getenv("IPINFO_TOKEN", "")
        url = f"https://ipinfo.io/{ip_address}/json"
        if token:
            url = f"{url}?token={token}"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            payload = response.json()
            return EndpointResult(
                endpoint=self.name,
                cost=self.cost_per_call,
                success=True,
                data={
                    "asn": payload.get("org", "").split()[0] if payload.get("org") else None,
                    "org": payload.get("org"),
                    "country": payload.get("country"),
                    "hostname": payload.get("hostname"),
                    "source": "ipinfo.io",
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
