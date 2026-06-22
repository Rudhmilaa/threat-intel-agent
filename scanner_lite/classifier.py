"""4-category outcome classifier: benign, malicious, suspicious, unknown."""

from __future__ import annotations

from typing import Any

OUTCOME_CATEGORIES = ("benign", "malicious", "suspicious", "unknown")

CLASSIFIABLE_CONFIDENCE = {"high", "medium"}


def classify_outcome(signals: dict[str, Any]) -> dict:
    """
    Deterministic 4-bucket classifier (first strong match wins).

    signals keys: scanner_tag, greynoise, abuseipdb, otx, anonymizer, timeline
    """
    scanner = signals.get("scanner_tag") or {}
    greynoise = signals.get("greynoise") or {}
    abuse = signals.get("abuseipdb") or {}
    otx = signals.get("otx") or {}

    gn_class = (
        greynoise.get("noise_classification")
        or greynoise.get("classification")
        or ""
    ).lower()

    abuse_score = abuse.get("abuse_confidence_score", 0) or 0
    threat_types = [t.lower() for t in abuse.get("threat_types", [])]
    malware = abuse.get("known_malware_associations", []) or []
    total_reports = abuse.get("total_reports", 0) or 0
    pulse_count = otx.get("pulse_count", 0) or 0

    is_known_scanner = scanner.get("is_known_scanner") is True
    confidence = (scanner.get("confidence") or "").lower()

    reasons: list[str] = []

    # Malicious
    if gn_class == "malicious":
        reasons.append("GreyNoise classification is malicious.")
        return _result("malicious", 0.9, reasons)

    if any(t in threat_types for t in ("botnet_c2", "malware_distribution", "apt_c2")):
        reasons.append("Reputation threat types indicate malicious infrastructure.")
        return _result("malicious", 0.92, reasons)

    if abuse_score >= 85 and malware:
        reasons.append("High abuse score with known malware associations.")
        return _result("malicious", 0.88, reasons)

    if pulse_count >= 5 and not is_known_scanner:
        reasons.append("OTX pulse activity without scanner attribution.")
        return _result("malicious", 0.75, reasons)

    # Benign
    if is_known_scanner and confidence in CLASSIFIABLE_CONFIDENCE:
        reasons.append(
            f"Known scanner: {scanner.get('company', 'unknown')} "
            f"({scanner.get('matched_range', '')})"
        )
        return _result("benign", 0.95, reasons)

    if gn_class in ("benign_scanner", "benign"):
        reasons.append("GreyNoise indicates benign scanner traffic.")
        return _result("benign", 0.85, reasons)

    if is_known_scanner:
        reasons.append(f"Known scanner (lower confidence): {scanner.get('company')}")
        return _result("benign", 0.7, reasons)

    # Suspicious
    if gn_class == "suspicious":
        reasons.append("GreyNoise classification is suspicious.")
        return _result("suspicious", 0.8, reasons)

    if abuse_score >= 60 or total_reports >= 100:
        reasons.append("Elevated abuse score or report volume without scanner tag.")
        return _result("suspicious", 0.75, reasons)

    network_type = (signals.get("anonymizer") or {}).get("network_type", "")
    if network_type == "bulletproof_hosting":
        reasons.append("Bulletproof hosting context.")
        return _result("suspicious", 0.7, reasons)

    # Honeypot behavioral signals
    hp = signals.get("honeypot") or {}
    behavior_tags = hp.get("behavior_tags") or []

    if "peoplesoft_probe" in behavior_tags and "go_http_client" in behavior_tags:
        reasons.append("Targeted PeopleSoft fingerprinting from unbranded Go HTTP client.")
        return _result("suspicious", 0.82, reasons)

    if "application_layer_recon" in behavior_tags and not is_known_scanner:
        reasons.append("Application-layer reconnaissance without known scanner attribution.")
        return _result("suspicious", 0.75, reasons)

    # Unknown
    reasons.append("No strong benign, malicious, or suspicious signal.")
    return _result("unknown", 0.4, reasons)


def _result(category: str, confidence: float, reasons: list[str]) -> dict:
    return {
        "outcome_category": category,
        "confidence": round(confidence, 2),
        "reasons": reasons,
    }


def build_scanner_tag(scanner_data: dict) -> dict | None:
    if not scanner_data.get("is_known_scanner"):
        return None
    return {
        "vendor": scanner_data.get("company"),
        "scanner_id": scanner_data.get("scanner_id"),
        "scanner_type": scanner_data.get("category"),
        "matched_cidr": scanner_data.get("matched_range"),
        "confidence": scanner_data.get("confidence"),
        "classification": scanner_data.get("classification"),
        "source_url": scanner_data.get("source_url"),
    }
