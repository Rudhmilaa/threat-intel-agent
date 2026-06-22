"""Endpoint registry and default cascade order."""

from __future__ import annotations

from typing import Optional

from scanner_lite.endpoints.abuseipdb import AbuseIpdbAdapter
from scanner_lite.endpoints.greynoise import GreynoiseAdapter
from scanner_lite.endpoints.ip_api import IpApiAdapter
from scanner_lite.endpoints.ipinfo import IpinfoAdapter
from scanner_lite.endpoints.local_csv import LocalCsvAdapter
from scanner_lite.endpoints.otx import OtxAdapter
from scanner_lite.endpoints.ripestat import RipestatAdapter
from scanner_lite.endpoints.shodan_internetdb import ShodanInternetdbAdapter

ADAPTERS = {
    "local_csv": LocalCsvAdapter(),
    "ripestat": RipestatAdapter(),
    "ip_api": IpApiAdapter(),
    "greynoise": GreynoiseAdapter(),
    "abuseipdb": AbuseIpdbAdapter(),
    "shodan_internetdb": ShodanInternetdbAdapter(),
    "otx": OtxAdapter(),
    "ipinfo": IpinfoAdapter(),
}

# Default paid cascade after local_csv (overridden by eval/ranking.json when present)
DEFAULT_CASCADE = ["greynoise", "abuseipdb", "otx"]

ENDPOINT_ORDER = list(ADAPTERS.keys())


def get_adapter(name: str):
    return ADAPTERS.get(name)


def list_adapters() -> list[str]:
    return list(ADAPTERS.keys())
