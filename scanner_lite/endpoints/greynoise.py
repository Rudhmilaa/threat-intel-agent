"""GreyNoise Community-style classification — mock fallback when no API key."""

from __future__ import annotations

import os

import requests

from scanner_lite.endpoints.base import EndpointResult
from threat_intel.lookups import classify_greynoise


class GreynoiseAdapter:
    name = "greynoise"
    cost_per_call = 0.0

    def query(self, ip_address: str) -> EndpointResult:
        api_key = os.getenv("GREYNOISE_API_KEY")
        if api_key:
            try:
                response = requests.get(
                    f"https://api.greynoise.io/v3/community/{ip_address}",
                    headers={"key": api_key, "Accept": "application/json"},
                    timeout=10,
                )
                if response.status_code == 404:
                    data = {"classification": "unknown", "noise_classification": "unknown"}
                else:
                    response.raise_for_status()
                    raw = response.json()
                    data = {
                        "classification": raw.get("classification", "unknown"),
                        "noise_classification": raw.get("classification", "unknown"),
                        "actor": raw.get("name"),
                        "source": "GreyNoise",
                    }
                return EndpointResult(
                    endpoint=self.name,
                    cost=self.cost_per_call,
                    success=True,
                    data=data,
                )
            except Exception as error:
                return EndpointResult(
                    endpoint=self.name,
                    cost=self.cost_per_call,
                    success=False,
                    data={},
                    error=str(error),
                )

        mock = classify_greynoise(ip_address)
        return EndpointResult(
            endpoint=self.name,
            cost=self.cost_per_call,
            success=True,
            data={
                "classification": mock.get("classification", "unknown"),
                "noise_classification": mock.get("classification", "unknown"),
                "actor": mock.get("actor"),
                "source": "GreyNoise-mock",
            },
        )
