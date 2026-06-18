"""Investigation outcome classification."""

from __future__ import annotations

from threat_intel.lookups import (
    classify_anonymizer_network,
    classify_greynoise,
    lookup_ioc_timeline,
    lookup_ip_reputation,
    lookup_ip_reputation_abuseipdb,
)
from threat_intel.scanners import classify_known_scanner

def classify_investigation_outcome(
    reputation_data: dict,
    scanner_data: dict = None,
    anonymizer_data: dict = None,
    greynoise_data: dict = None,
    timeline_data: dict = None,
) -> dict:
    """
    Classifies what kind of investigation this is.

    This is different from severity scoring.
    It explains the nature of the activity.
    """

    scanner_data = scanner_data or {}
    anonymizer_data = anonymizer_data or {}
    greynoise_data = greynoise_data or {}
    timeline_data = timeline_data or {}

    is_known_scanner = scanner_data.get("is_known_scanner", False)
    scanner_company = scanner_data.get("company")

    abuse_score = reputation_data.get("abuse_confidence_score", 0)
    total_reports = reputation_data.get("total_reports", 0)
    threat_types = reputation_data.get("threat_types", [])

    gn_classification = greynoise_data.get("classification")
    network_type = anonymizer_data.get("network_type")
    observation_count = timeline_data.get("observation_count", 0)

    reasons = []

    # Confirmed C2 / malware infrastructure
    if (
        "botnet_c2" in threat_types
        or "malware_distribution" in threat_types
        or gn_classification == "malicious"
    ):
        reasons.append("Indicator is associated with malicious infrastructure or malware activity.")
        return {
            "investigation_classification": "confirmed_malicious_infrastructure",
            "category": "malicious",
            "priority": "critical",
            "reasons": reasons,
        }

    # Known scanner with lots of reports
    if is_known_scanner and total_reports >= 100:
        reasons.append(f"IP belongs to known scanner infrastructure: {scanner_company}.")
        reasons.append("High report volume is likely caused by internet-wide scanning behavior.")
        return {
            "investigation_classification": "known_scanner_high_noise",
            "category": "benign_but_noisy",
            "priority": "low",
            "reasons": reasons,
        }

    # Known scanner with low/no reports
    if is_known_scanner:
        reasons.append(f"IP belongs to known scanner infrastructure: {scanner_company}.")
        return {
            "investigation_classification": "known_scanner",
            "category": "benign_scanner",
            "priority": "informational",
            "reasons": reasons,
        }

    # Tor / VPN / anonymizer
    if network_type == "tor_exit_node":
        reasons.append("Traffic originated from Tor exit infrastructure.")
        return {
            "investigation_classification": "anonymized_traffic_tor",
            "category": "anonymizer",
            "priority": "medium",
            "reasons": reasons,
        }

    if network_type == "commercial_vpn":
        reasons.append("Traffic originated from commercial VPN infrastructure.")
        return {
            "investigation_classification": "anonymized_traffic_vpn",
            "category": "anonymizer",
            "priority": "low",
            "reasons": reasons,
        }

    if network_type == "bulletproof_hosting":
        reasons.append("Infrastructure is associated with suspicious or abuse-resistant hosting.")
        return {
            "investigation_classification": "suspicious_hosting",
            "category": "suspicious_infrastructure",
            "priority": "high",
            "reasons": reasons,
        }

    # Abuse but no known scanner attribution
    if abuse_score >= 70 or total_reports >= 100:
        reasons.append("Indicator has high abuse score or high report volume without known benign scanner attribution.")
        return {
            "investigation_classification": "active_reconnaissance_or_abuse",
            "category": "suspicious",
            "priority": "high",
            "reasons": reasons,
        }

    # GreyNoise benign scanner
    if gn_classification == "benign_scanner":
        reasons.append("GreyNoise-style classification indicates benign scanner or internet noise.")
        return {
            "investigation_classification": "benign_internet_noise",
            "category": "benign_noise",
            "priority": "informational",
            "reasons": reasons,
        }

    # Unknown
    reasons.append("No strong malicious, benign scanner, or anonymizer classification found.")
    return {
        "investigation_classification": "unknown",
        "category": "unknown",
        "priority": "review",
        "reasons": reasons,
    }

def classify_investigation_outcome_tool(ip_address: str) -> dict:
    reputation_data = lookup_ip_reputation_abuseipdb(ip_address)

    # If AbuseIPDB fails or no key exists, fall back to mock reputation.
    if "error" in reputation_data:
        reputation_data = lookup_ip_reputation(ip_address)

    scanner_data = classify_known_scanner(ip_address)
    anonymizer_data = classify_anonymizer_network(ip_address)
    greynoise_data = classify_greynoise(ip_address)
    timeline_data = lookup_ioc_timeline(ip_address, "ip_address")

    return classify_investigation_outcome(
        reputation_data=reputation_data,
        scanner_data=scanner_data,
        anonymizer_data=anonymizer_data,
        greynoise_data=greynoise_data,
        timeline_data=timeline_data,
    )
