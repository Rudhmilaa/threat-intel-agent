"""Automated maintenance for known_scanner_inventory.csv."""

from __future__ import annotations

import csv
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

import requests

from threat_intel.scanners import (
    CLIENT_SCANNERS_DIR,
    DEFAULT_SCANNER_INVENTORY_PATH,
    INVENTORY_COLUMNS,
    SCANNER_FEED_SNAPSHOT_DIR,
    ScannerRegistry,
    configure_scanners,
    inventory_to_scanner_entries,
    load_scanner_inventory,
)

CIDR_PATTERN = re.compile(
    r"(?<![0-9a-fA-F:])(?:(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}|(?:[0-9a-fA-F:]+:+)+/[0-9]{1,3})(?![0-9a-fA-F:])"
)

BINARYEDGE_SCANNER_URLS = (
    "https://api.binaryedge.io/v1/minions",
)

# Vendor pages that are JS-rendered or intermittently unavailable. These are the
# officially published ranges used only when live parsing fails.
XPANSE_DOCUMENTED_CIDRS = (
    "35.203.210.0/23",
    "144.86.173.0/24",
    "147.185.132.0/23",
    "162.216.149.0/24",
    "162.216.150.0/24",
    "172.105.147.0/24",
    "198.235.24.0/24",
    "205.210.31.0/24",
    "216.25.88.0/21",
    "2604:a940:300:5b6::/64",
    "2604:a940:301:225::/64",
    "2604:a940:302:118::/64",
)

ONYPHE_DOCUMENTED_CIDRS = (
    "51.81.26.64/28",
    "51.81.253.64/28",
    "51.81.228.240/28",
    "147.135.58.160/28",
    "51.81.14.224/28",
    "51.81.218.64/28",
    "147.135.26.176/28",
)

ONYPHE_PROBE_URLS = (
    "http://scanner3us-10.tmhcc.probe.onyphe.net/",
    "https://www.onyphe.io/",
)

PENDING_VENDORS = (
    "Google Security Research",
    "Microsoft Defender Research",
    "AWS Security Research",
    "Akamai Research",
    "Cloudflare Research",
)

MANUAL_VENDORS = {"The Shadowserver Foundation"}

# Large rotating scanner feeds are stored as JSON snapshots instead of CSV rows.
FEED_SNAPSHOT_VENDORS = {"BinaryEdge", "Stretchoid", "hunter.how", "FOFA"}


@dataclass
class FeedResult:
    vendor: str
    scanner_type: str
    source_url: str
    confidence: str
    cidrs: list[str] = field(default_factory=list)
    status: str = "ok"
    message: str = ""


@dataclass
class MaintenanceReport:
    inventory_path: str
    refreshed_at: str
    last_verified: str
    feeds: list[FeedResult] = field(default_factory=list)
    pending_checks: list[dict] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        payload = {
            "inventory_path": self.inventory_path,
            "refreshed_at": self.refreshed_at,
            "last_verified": self.last_verified,
            "summary": self.summary,
            "feeds": [
                {
                    "vendor": feed.vendor,
                    "scanner_type": feed.scanner_type,
                    "source_url": feed.source_url,
                    "confidence": feed.confidence,
                    "cidr_count": len(feed.cidrs),
                    "status": feed.status,
                    "message": feed.message,
                }
                for feed in self.feeds
            ],
            "pending_checks": self.pending_checks,
            "errors": self.errors,
        }
        if self.summary.get("inventory_backend") is not None:
            payload["inventory_backend"] = self.summary["inventory_backend"]
        if self.summary.get("inventory_version") is not None:
            payload["inventory_version"] = self.summary["inventory_version"]
        if self.summary.get("es_sync") is not None:
            payload["es_sync"] = self.summary["es_sync"]
        if self.summary.get("redis_refreshed_at") is not None:
            payload["redis_refreshed_at"] = self.summary["redis_refreshed_at"]
        return payload


def current_verification_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m")


def _fetch_text(url: str, timeout: int = 20) -> str:
    response = requests.get(
        url,
        timeout=timeout,
        headers={"User-Agent": "threat-intel-agent-scanner-maintenance/1.0"},
    )
    response.raise_for_status()
    return response.text


def _fetch_json(url: str, timeout: int = 20) -> object:
    response = requests.get(
        url,
        timeout=timeout,
        headers={"User-Agent": "threat-intel-agent-scanner-maintenance/1.0"},
    )
    response.raise_for_status()
    return response.json()


def _extract_cidrs(text: str) -> list[str]:
    found: list[str] = []
    for match in CIDR_PATTERN.findall(text):
        try:
            network = ipaddress.ip_network(match.replace("0:0:0:0", "::"), strict=False)
        except ValueError:
            continue
        normalized = str(network)
        if normalized not in found:
            found.append(normalized)
    return found


def _ip_to_host_cidr(value: str) -> Optional[str]:
    try:
        return f"{ipaddress.ip_address(value)}/32"
    except ValueError:
        return None


def fetch_censys_feed() -> FeedResult:
    url = "https://docs.censys.com/docs/opt-out-of-data-collection"
    try:
        text = _fetch_text(url)
        cidrs = _extract_cidrs(text)
        if not cidrs:
            raise ValueError("No CIDR blocks found in Censys opt-out documentation.")
        return FeedResult(
            vendor="Censys",
            scanner_type="internet_measurement",
            source_url=url,
            confidence="high",
            cidrs=cidrs,
        )
    except (requests.RequestException, ValueError) as exc:
        return FeedResult(
            vendor="Censys",
            scanner_type="internet_measurement",
            source_url=url,
            confidence="high",
            status="error",
            message=str(exc),
        )


def fetch_xpanse_feed() -> FeedResult:
    url = (
        "https://docs-cortex.paloaltonetworks.com/r/Cortex-XPANSE/2/"
        "Cortex-Xpanse-Expander-User-Guide/Scanning-activity"
    )
    message = ""
    try:
        text = _fetch_text(url)
        cidrs = _extract_cidrs(text)
        if not cidrs:
            cidrs = list(XPANSE_DOCUMENTED_CIDRS)
            message = "Vendor page is JS-rendered; used documented Palo Alto fallback ranges."
    except (requests.RequestException, ValueError) as exc:
        cidrs = list(XPANSE_DOCUMENTED_CIDRS)
        message = f"{exc}; used documented Palo Alto fallback ranges."

    if not cidrs:
        return FeedResult(
            vendor="Palo Alto Networks Cortex Xpanse",
            scanner_type="attack_surface_scanning",
            source_url=url,
            confidence="high",
            status="error",
            message=message or "No Cortex Xpanse ranges available.",
        )

    return FeedResult(
        vendor="Palo Alto Networks Cortex Xpanse",
        scanner_type="attack_surface_scanning",
        source_url=url,
        confidence="high",
        cidrs=cidrs,
        message=message,
    )


def fetch_onyphe_feed() -> FeedResult:
    source_url = ONYPHE_PROBE_URLS[0]
    errors: list[str] = []
    cidrs: list[str] = []

    for candidate in ONYPHE_PROBE_URLS:
        source_url = candidate
        try:
            text = _fetch_text(candidate)
            cidrs = _extract_cidrs(text)
            if cidrs:
                return FeedResult(
                    vendor="ONYPHE",
                    scanner_type="exposure_scanning",
                    source_url=candidate,
                    confidence="high",
                    cidrs=cidrs,
                )
            errors.append(f"{candidate}: no CIDR blocks found")
        except (requests.RequestException, ValueError) as exc:
            errors.append(f"{candidate}: {exc}")

    return FeedResult(
        vendor="ONYPHE",
        scanner_type="exposure_scanning",
        source_url=source_url,
        confidence="high",
        cidrs=list(ONYPHE_DOCUMENTED_CIDRS),
        message="; ".join(errors) + "; used documented ONYPHE fallback ranges.",
    )


def fetch_leakix_feed() -> FeedResult:
    url = "https://scan.leakix.net/json"
    try:
        payload = _fetch_json(url)
        probes = payload.get("probes", []) if isinstance(payload, dict) else []
        cidrs: list[str] = []
        for probe in probes:
            if not isinstance(probe, dict):
                continue
            host_cidr = _ip_to_host_cidr(str(probe.get("ipv4", "")).strip())
            if host_cidr and host_cidr not in cidrs:
                cidrs.append(host_cidr)
        if not cidrs:
            raise ValueError("LeakIX probe feed returned no IPv4 addresses.")
        return FeedResult(
            vendor="LeakIX",
            scanner_type="exposure_scanning",
            source_url=url,
            confidence="medium",
            cidrs=sorted(cidrs, key=ipaddress.ip_network),
        )
    except (requests.RequestException, ValueError, json.JSONDecodeError) as exc:
        return FeedResult(
            vendor="LeakIX",
            scanner_type="exposure_scanning",
            source_url=url,
            confidence="medium",
            status="error",
            message=str(exc),
        )


def fetch_binaryedge_feed() -> FeedResult:
    source_url = BINARYEDGE_SCANNER_URLS[0]
    errors: list[str] = []
    for candidate in BINARYEDGE_SCANNER_URLS:
        source_url = candidate
        try:
            payload = _fetch_json(candidate)
            scanners = payload.get("scanners", []) if isinstance(payload, dict) else payload
            if not isinstance(scanners, list):
                raise ValueError("Unexpected BinaryEdge scanner feed format.")
            cidrs: list[str] = []
            for item in scanners:
                value = str(item).strip()
                if "/" in value:
                    network = ipaddress.ip_network(value, strict=False)
                    normalized = str(network)
                else:
                    host_cidr = _ip_to_host_cidr(value)
                    if not host_cidr:
                        continue
                    normalized = host_cidr
                if normalized not in cidrs:
                    cidrs.append(normalized)
            if not cidrs:
                raise ValueError("BinaryEdge scanner feed returned no addresses.")
            return FeedResult(
                vendor="BinaryEdge",
                scanner_type="internet_scanning",
                source_url=candidate,
                confidence="medium",
                cidrs=sorted(cidrs, key=ipaddress.ip_network),
            )
        except (requests.RequestException, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"{candidate}: {exc}")
    return FeedResult(
        vendor="BinaryEdge",
        scanner_type="internet_scanning",
        source_url=source_url,
        confidence="medium",
        status="error",
        message="; ".join(errors) or "BinaryEdge scanner feed unavailable.",
    )


def check_source_url(url: str, timeout: int = 15) -> tuple[bool, str]:
    if not url:
        return False, "missing source_url"
    try:
        response = requests.head(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "threat-intel-agent-scanner-maintenance/1.0"},
        )
        if response.status_code in {401, 403, 405} or response.ok:
            return True, f"HTTP {response.status_code}"
        return False, f"HTTP {response.status_code}"
    except requests.RequestException as exc:
        try:
            response = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "threat-intel-agent-scanner-maintenance/1.0"},
            )
            if response.ok:
                return True, f"HTTP {response.status_code}"
            return False, f"HTTP {response.status_code}"
        except requests.RequestException as get_exc:
            return False, str(get_exc)


AUTO_MANAGED_FEEDS: list[Callable[[], FeedResult]] = [
    fetch_censys_feed,
    fetch_xpanse_feed,
    fetch_onyphe_feed,
    fetch_leakix_feed,
    fetch_binaryedge_feed,
]


def _rows_for_feed(feed: FeedResult, last_verified: str) -> list[dict]:
    return [
        {
            "vendor": feed.vendor,
            "scanner_type": feed.scanner_type,
            "cidr": cidr,
            "source_url": feed.source_url,
            "last_verified": last_verified,
            "confidence": feed.confidence,
        }
        for cidr in feed.cidrs
    ]


def _placeholder_row(row: dict, last_verified: str, source_reachable: bool) -> dict:
    updated = dict(row)
    updated["cidr"] = ""
    if source_reachable:
        updated["last_verified"] = last_verified
    return updated


def _feed_snapshot_path(vendor: str) -> Path:
    slug = vendor.lower().replace(" ", "-")
    return SCANNER_FEED_SNAPSHOT_DIR / f"{slug}.json"


def feed_to_snapshot_dict(feed: FeedResult, last_verified: str) -> dict:
    return {
        "vendor": feed.vendor,
        "scanner_type": feed.scanner_type,
        "source_url": feed.source_url,
        "last_verified": last_verified,
        "confidence": feed.confidence,
        "refreshed_at": datetime.now(timezone.utc).isoformat(),
        "cidr_count": len(feed.cidrs),
        "cidrs": feed.cidrs,
    }


def write_feed_snapshot(feed: FeedResult, last_verified: str) -> Path:
    SCANNER_FEED_SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    snapshot_path = _feed_snapshot_path(feed.vendor)
    payload = feed_to_snapshot_dict(feed, last_verified)
    snapshot_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return snapshot_path


def merge_inventory_rows(
    existing_rows: list[dict],
    feeds: list[FeedResult],
    pending_checks: list[dict],
    last_verified: str,
    previous_feed_snapshots: Optional[dict[str, dict]] = None,
) -> tuple[list[dict], dict, list[FeedResult]]:
    preserved_rows = [row for row in existing_rows if row["vendor"] in MANUAL_VENDORS]

    managed_rows: list[dict] = []
    feed_snapshots: list[FeedResult] = []
    feed_stats = {"updated": 0, "unchanged": 0, "failed": 0, "added_ranges": 0, "removed_ranges": 0}

    for feed in feeds:
        previous = [row for row in existing_rows if row["vendor"] == feed.vendor]
        previous_cidrs = {row["cidr"] for row in previous if row.get("cidr")}

        if feed.status != "ok":
            feed_stats["failed"] += 1
            managed_rows.extend(previous or [_placeholder_row(
                {
                    "vendor": feed.vendor,
                    "scanner_type": feed.scanner_type,
                    "cidr": "",
                    "source_url": feed.source_url,
                    "last_verified": last_verified,
                    "confidence": "dynamic" if feed.vendor in FEED_SNAPSHOT_VENDORS else feed.confidence,
                },
                last_verified,
                False,
            )])
            continue

        if feed.vendor in FEED_SNAPSHOT_VENDORS:
            previous_snapshot = (previous_feed_snapshots or {}).get(feed.vendor, {})
            if not previous_snapshot:
                snapshot_path = _feed_snapshot_path(feed.vendor)
                if snapshot_path.exists():
                    previous_snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
            previous_cidrs = set(previous_snapshot.get("cidrs", []))
            next_cidrs = set(feed.cidrs)
            feed_stats["added_ranges"] += len(next_cidrs - previous_cidrs)
            feed_stats["removed_ranges"] += len(previous_cidrs - next_cidrs)
            if next_cidrs == previous_cidrs:
                feed_stats["unchanged"] += 1
            else:
                feed_stats["updated"] += 1
            feed_snapshots.append(feed)
            managed_rows.append(
                {
                    "vendor": feed.vendor,
                    "scanner_type": feed.scanner_type,
                    "cidr": "",
                    "source_url": feed.source_url,
                    "last_verified": last_verified,
                    "confidence": "dynamic",
                }
            )
            continue

        next_rows = _rows_for_feed(feed, last_verified)
        next_cidrs = {row["cidr"] for row in next_rows}
        feed_stats["added_ranges"] += len(next_cidrs - previous_cidrs)
        feed_stats["removed_ranges"] += len(previous_cidrs - next_cidrs)
        if next_cidrs == previous_cidrs:
            feed_stats["unchanged"] += 1
        else:
            feed_stats["updated"] += 1
        managed_rows.extend(next_rows)

    pending_rows = []
    for vendor in PENDING_VENDORS:
        current = next((row for row in existing_rows if row["vendor"] == vendor), None)
        if not current:
            continue
        source_url = current.get("source_url", "")
        reachable, detail = check_source_url(source_url)
        pending_rows.append(_placeholder_row(current, last_verified, reachable))
        pending_checks.append(
            {
                "vendor": vendor,
                "source_url": source_url,
                "reachable": reachable,
                "detail": detail,
            }
        )

    merged_rows = preserved_rows + managed_rows + pending_rows
    return merged_rows, feed_stats, feed_snapshots


def write_scanner_inventory(rows: list[dict], inventory_path: Path = DEFAULT_SCANNER_INVENTORY_PATH) -> None:
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    with inventory_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(INVENTORY_COLUMNS))
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in INVENTORY_COLUMNS})


def _load_existing_inventory_rows(
    inventory_path: Path,
    *,
    seed_from_files: bool = False,
) -> tuple[list[dict], dict[str, dict], str]:
    from threat_intel.scanner_redis_store import get_scanner_redis_store, scanner_inventory_backend

    backend = scanner_inventory_backend()
    if backend != "redis":
        return load_scanner_inventory(inventory_path), {}, "file"

    store = get_scanner_redis_store()
    if seed_from_files or not store.is_populated():
        store.publish_from_files(inventory_path=inventory_path)

    existing_rows = store.load_csv_rows()
    previous_snapshots = {
        snap.get("vendor", ""): snap
        for snap in store.load_all_feed_snapshots()
        if snap.get("vendor")
    }
    return existing_rows, previous_snapshots, "redis"


def _compile_registry_for_clients(
    merged_rows: list[dict],
    feed_snapshot_payloads: list[dict],
    client_ids: Optional[list[str]] = None,
) -> dict[str, list[dict]]:
    feed_rows = []
    for payload in feed_snapshot_payloads:
        vendor = payload.get("vendor", "")
        for cidr in payload.get("cidrs", []):
            feed_rows.append(
                {
                    "vendor": vendor,
                    "scanner_type": payload.get("scanner_type", "internet_scanning"),
                    "cidr": cidr,
                    "source_url": payload.get("source_url", ""),
                    "last_verified": payload.get("last_verified", ""),
                    "confidence": payload.get("confidence", "medium"),
                }
            )

    default_entries = inventory_to_scanner_entries(merged_rows, feed_rows)
    compiled: dict[str, list[dict]] = {}
    for client_id in client_ids or ["scanner-lite"]:
        client_scanners = []
        client_path = CLIENT_SCANNERS_DIR / f"{client_id}_scanners.json"
        if client_path.exists():
            client_payload = json.loads(client_path.read_text(encoding="utf-8"))
            client_scanners = client_payload.get("scanners", [])
        merged = {entry["id"]: entry for entry in default_entries}
        for entry in client_scanners:
            merged[entry["id"]] = entry
        compiled[client_id] = list(merged.values())
    return compiled


def refresh_scanner_inventory(
    inventory_path: Path = DEFAULT_SCANNER_INVENTORY_PATH,
    write_changes: bool = True,
    reload_registry: bool = True,
    feeds: Optional[list[Callable[[], FeedResult]]] = None,
    *,
    export_files: bool = False,
    skip_es: bool = False,
    seed_from_files: bool = False,
) -> MaintenanceReport:
    """
    Refresh auto-managed vendor feeds, verify pending vendor documentation URLs,
    publish to Redis (primary), sync Elasticsearch, and optionally export CSV/JSON files.
    """
    existing_rows, previous_snapshots, backend = _load_existing_inventory_rows(
        inventory_path,
        seed_from_files=seed_from_files,
    )
    last_verified = current_verification_stamp()
    report = MaintenanceReport(
        inventory_path=str(inventory_path),
        refreshed_at=datetime.now(timezone.utc).isoformat(),
        last_verified=last_verified,
    )

    feed_results = [feed() for feed in (feeds or AUTO_MANAGED_FEEDS)]
    report.feeds = feed_results

    merged_rows, feed_stats, feed_snapshots = merge_inventory_rows(
        existing_rows,
        feed_results,
        report.pending_checks,
        last_verified,
        previous_feed_snapshots=previous_snapshots,
    )

    updated_snapshot_vendors = {feed.vendor for feed in feed_snapshots}
    feed_snapshot_payloads = [
        feed_to_snapshot_dict(feed, last_verified) for feed in feed_snapshots
    ]
    for vendor, snapshot in previous_snapshots.items():
        if vendor and vendor not in updated_snapshot_vendors:
            feed_snapshot_payloads.append(snapshot)

    report.summary = {
        "row_count_before": len(existing_rows),
        "row_count_after": len(merged_rows),
        "classifiable_ranges_after": sum(
            1
            for row in merged_rows
            if row.get("cidr") and row.get("confidence", "").lower() in {"high", "medium"}
        ),
        "feed_snapshot_count": len(feed_snapshot_payloads),
        "inventory_backend": backend,
        **feed_stats,
    }

    for feed in feed_results:
        if feed.status != "ok":
            report.errors.append(f"{feed.vendor}: {feed.message}")

    if write_changes:
        if backend == "redis":
            from threat_intel.scanner_redis_store import get_scanner_redis_store

            store = get_scanner_redis_store()
            compiled = _compile_registry_for_clients(merged_rows, feed_snapshot_payloads)
            meta = store.publish_inventory(merged_rows, feed_snapshot_payloads, compiled)
            report.summary["inventory_version"] = meta.get("version")
            report.summary["redis_refreshed_at"] = meta.get("refreshed_at")

            if not skip_es:
                from scanner_lite.storage.inventory_es_store import ScannerInventoryEsStore

                payload = store.build_publish_payload()
                es_result = ScannerInventoryEsStore().sync_from_publish(payload)
                store.update_es_sync(es_result.get("index", ""), es_result.get("indexed", 0))
                report.summary["es_sync"] = es_result

            if export_files:
                export_stats = store.export_to_files(inventory_path, SCANNER_FEED_SNAPSHOT_DIR)
                report.summary["export_files"] = export_stats
        else:
            write_scanner_inventory(merged_rows, inventory_path)
            for feed in feed_snapshots:
                write_feed_snapshot(feed, last_verified)

    if reload_registry and write_changes:
        configure_scanners(ScannerRegistry.for_client())

    return report


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Refresh known scanner inventory from official vendor feeds.")
    parser.add_argument(
        "--inventory-path",
        default=str(DEFAULT_SCANNER_INVENTORY_PATH),
        help="Path to known_scanner_inventory.csv",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch feeds and print a report without publishing inventory.",
    )
    parser.add_argument(
        "--export-files",
        action="store_true",
        help="After Redis publish, export CSV and feed JSON to disk for git review.",
    )
    parser.add_argument(
        "--skip-es",
        action="store_true",
        help="Publish to Redis only; skip Elasticsearch scanner-inventory sync.",
    )
    parser.add_argument(
        "--seed-from-files",
        action="store_true",
        help="Force bootstrap Redis from on-disk CSV and feed snapshots before merge.",
    )
    args = parser.parse_args()

    report = refresh_scanner_inventory(
        inventory_path=Path(args.inventory_path),
        write_changes=not args.dry_run,
        reload_registry=not args.dry_run,
        export_files=args.export_files,
        skip_es=args.skip_es,
        seed_from_files=args.seed_from_files,
    )
    print(json.dumps(report.to_dict(), indent=2))
    return 1 if report.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
