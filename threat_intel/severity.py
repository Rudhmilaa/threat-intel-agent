"""Enriched severity scoring."""

from __future__ import annotations

from threat_intel.lookups import (
    classify_anonymizer_network,
    classify_greynoise,
    lookup_ioc_timeline,
    lookup_ip_reputation,
)
from threat_intel.scanners import classify_known_scanner

def calculate_enriched_severity(
    reputation_data: dict,
    scanner_data: dict = None,
    anonymizer_data: dict = None,
    greynoise_data: dict = None,
    timeline_data: dict = None,
) -> dict:
    """
    Calculates a richer threat score using multiple enrichment sources.

    This combines:
    - reputation data
    - known scanner classification
    - Tor/VPN/proxy classification
    - GreyNoise-style classification
    - IOC timeline counts
    """

    scanner_data = scanner_data or {}
    anonymizer_data = anonymizer_data or {}
    greynoise_data = greynoise_data or {}
    timeline_data = timeline_data or {}

    threat_score = 0
    confidence_score = 0
    risk_factors = []

    # 1. Reputation score
    abuse_score = reputation_data.get("abuse_confidence_score", 0)

    if abuse_score >= 90:
        threat_score += 35
        confidence_score += 25
        risk_factors.append("Very high abuse confidence score")
    elif abuse_score >= 70:
        threat_score += 25
        confidence_score += 20
        risk_factors.append("High abuse confidence score")
    elif abuse_score >= 40:
        threat_score += 15
        confidence_score += 10
        risk_factors.append("Moderate abuse confidence score")

    # 2. Threat types
    threat_types = reputation_data.get("threat_types", [])

    if threat_types:
        points = min(len(threat_types) * 8, 25)
        threat_score += points
        confidence_score += 15
        risk_factors.append(
            f"Observed threat types: {', '.join(threat_types)}"
        )

    # 3. Malware associations
    malware = reputation_data.get("known_malware_associations", [])

    if malware:
        threat_score += 25
        confidence_score += 20
        risk_factors.append(
            f"Associated malware families: {', '.join(malware)}"
        )

    # 4. Known scanner adjustment
    if scanner_data.get("is_known_scanner") is True:
        threat_score -= 30
        confidence_score += 20
        risk_factors.append(
            f"Known scanner infrastructure: {scanner_data.get('company')}"
        )

    # 5. Tor / VPN / proxy / bulletproof hosting
    network_type = anonymizer_data.get("network_type")

    if network_type == "tor_exit_node":
        threat_score += 20
        confidence_score += 10
        risk_factors.append("Traffic originated from Tor exit node")

    elif network_type == "commercial_vpn":
        threat_score += 10
        confidence_score += 8
        risk_factors.append("Traffic originated from commercial VPN infrastructure")

    elif network_type == "bulletproof_hosting":
        threat_score += 25
        confidence_score += 15
        risk_factors.append("Infrastructure associated with bulletproof hosting")

    # 6. GreyNoise-style classification
    gn_classification = greynoise_data.get("classification")

    if gn_classification == "malicious":
        threat_score += 30
        confidence_score += 25
        risk_factors.append("GreyNoise-style classification is malicious")

    elif gn_classification == "benign_scanner":
        threat_score -= 25
        confidence_score += 20
        risk_factors.append("GreyNoise-style classification indicates benign scanner")

    elif gn_classification == "suspicious":
        threat_score += 15
        confidence_score += 10
        risk_factors.append("GreyNoise-style classification is suspicious")

    # 7. Timeline counts
    observation_count = timeline_data.get("observation_count", 0)

    if observation_count >= 1000:
        threat_score += 15
        confidence_score += 15
        risk_factors.append("High historical observation count")
    elif observation_count >= 100:
        threat_score += 10
        confidence_score += 10
        risk_factors.append("Moderate historical observation count")
    elif observation_count > 0:
        threat_score += 5
        confidence_score += 5
        risk_factors.append("Limited historical observation count")

    trend = timeline_data.get("trend")

    if trend == "increasing":
        threat_score += 10
        risk_factors.append("Activity trend is increasing")

    # Normalize scores
    threat_score = max(0, min(threat_score, 100))
    confidence_score = max(0, min(confidence_score, 100))

    if threat_score >= 85:
        severity = "CRITICAL"
    elif threat_score >= 65:
        severity = "HIGH"
    elif threat_score >= 40:
        severity = "MEDIUM"
    elif threat_score >= 15:
        severity = "LOW"
    else:
        severity = "INFORMATIONAL"

    return {
        "threat_score": threat_score,
        "confidence_score": confidence_score,
        "severity": severity,
        "risk_factors": risk_factors,
    }

def calculate_enriched_severity_tool(ip_address: str) -> dict:
    reputation_data = lookup_ip_reputation(ip_address)
    scanner_data = classify_known_scanner(ip_address)
    anonymizer_data = classify_anonymizer_network(ip_address)
    greynoise_data = classify_greynoise(ip_address)
    timeline_data = lookup_ioc_timeline(ip_address, "ip_address")

    return calculate_enriched_severity(
        reputation_data=reputation_data,
        scanner_data=scanner_data,
        anonymizer_data=anonymizer_data,
        greynoise_data=greynoise_data,
        timeline_data=timeline_data,
    )
