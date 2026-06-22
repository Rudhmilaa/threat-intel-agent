"""Shodan InternetDB — free basic host context."""

from __future__ import annotations

import requests

from scanner_lite.endpoints.base import EndpointResult


class ShodanInternetdbAdapter:
    name = "shodan_internetdb"
    cost_per_call = 0.0

    def query(self, ip_address: str) -> EndpointResult:
        url = f"https://internetdb.shodan.io/{ip_address}"
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 404:
                return EndpointResult(
                    endpoint=self.name,
                    cost=self.cost_per_call,
                    success=True,
                    data={"ports": [], "tags": [], "source": "Shodan InternetDB"},
                )
            response.raise_for_status()
            payload = response.json()
            return EndpointResult(
                endpoint=self.name,
                cost=self.cost_per_call,
                success=True,
                data={
                    "ports": payload.get("ports", []),
                    "tags": payload.get("tags", []),
                    "vulns": list((payload.get("vulns") or {}).keys())[:10],
                    "source": "Shodan InternetDB",
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
