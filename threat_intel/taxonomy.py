"""Structured taxonomy tags for incidents and enriched documents."""

from __future__ import annotations

from typing import Optional

INTENT_BY_ATTACK_TYPE = {
    "ssh_bruteforce": "credential_attack",
    "telnet_probe": "credential_attack",
    "service_probe": "service_probe",
    "web_probe": "service_probe",
    "exploit_attempt": "exploit_attempt",
}

CREDENTIAL_ATTACK_TYPES = {"ssh_bruteforce", "telnet_probe"}


def _scanner_identity_tag(scanner_data: dict) -> str:
    if not scanner_data.get("is_known_scanner"):
        return "identity:unknown_external"

    scanner_id = scanner_data.get("scanner_id", "known_scanner")
    return f"identity:known_scanner.{scanner_id}"


def classify_excessive_probe(cluster: dict, scanner_data: Optional[dict] = None) -> bool:
    if scanner_data and not scanner_data.get("is_known_scanner"):
        return False

    attack_types = set(cluster.get("attack_types", []))
    event_count = cluster.get("event_count", 0)
    destination_ports = cluster.get("destination_ports", [])
    recurrence = cluster.get("recurrence") or {}
    historical_events = recurrence.get("historical_events", 0)

    if event_count >= 50:
        return True
    if len(destination_ports) >= 5:
        return True
    if historical_events >= 500:
        return True
    if attack_types.intersection(CREDENTIAL_ATTACK_TYPES):
        return True

    return False


def build_cluster_taxonomy(cluster: dict, scanner_data: Optional[dict] = None) -> dict:
    attack_types = cluster.get("attack_types", [])
    intents = sorted(
        {
            INTENT_BY_ATTACK_TYPE.get(attack_type, "unknown")
            for attack_type in attack_types
        }
    )

    identity = _scanner_identity_tag(scanner_data or {})
    intensity = "low"
    response = "suppress"
    classification_override = None

    recurrence = cluster.get("recurrence") or {}
    event_count = cluster.get("event_count", 0)
    historical_events = recurrence.get("historical_events", 0)
    trend = recurrence.get("trend", "unknown")

    if event_count >= 10 or historical_events >= 100:
        intensity = "moderate"
        response = "monitor"

    if classify_excessive_probe(cluster, scanner_data):
        intensity = "excessive"
        response = "monitor"
        classification_override = "known_scanner_excessive_probe"

    if trend == "increasing" and intensity != "excessive":
        intensity = "persistent_recurring"
        response = "rate_limit"

    tags = [identity]
    tags.extend(f"intent:{intent}" for intent in intents)
    tags.append(f"intensity:{intensity}")
    tags.append(f"response:{response}")

    policy_tags = cluster.get("policy_tags", [])
    tags.extend(policy_tags)

    return {
        "tags": list(dict.fromkeys(tags)),
        "identity": identity,
        "intents": intents,
        "intensity": intensity,
        "response": response,
        "classification_override": classification_override,
    }


def attach_taxonomy_to_clusters(
    clusters: list[dict],
    scanner_lookup: Optional[dict[str, dict]] = None,
) -> list[dict]:
    scanner_lookup = scanner_lookup or {}

    for cluster in clusters:
        source_ip = cluster.get("source_ip")
        scanner_data = scanner_lookup.get(source_ip)

        if scanner_data is None:
            from threat_intel.scanners import classify_known_scanner

            scanner_data = classify_known_scanner(source_ip)

        taxonomy = build_cluster_taxonomy(cluster, scanner_data)
        cluster["taxonomy"] = taxonomy

        if taxonomy.get("classification_override"):
            cluster["investigation_classification"] = taxonomy["classification_override"]
            cluster["category"] = "benign_but_noisy"
            cluster["priority"] = "medium"

    return clusters


def attach_taxonomy_to_document(document: dict, taxonomy: dict) -> dict:
    document = dict(document)
    document["taxonomy"] = taxonomy
    return document


def build_document_taxonomy(document: dict, scanner_data: Optional[dict] = None) -> dict:
    """Lightweight per-document taxonomy tags for Elasticsearch documents."""
    attack_type = document.get("stingar", {}).get("attack_type") or document.get("attack", {}).get("type")
    intents = []
    if attack_type:
        intents.append(INTENT_BY_ATTACK_TYPE.get(attack_type, "unknown"))

    if scanner_data is None:
        source_ip = document.get("source", {}).get("ip")
        if source_ip:
            from threat_intel.scanners import classify_known_scanner

            scanner_data = classify_known_scanner(source_ip)
        else:
            scanner_data = {}

    identity = _scanner_identity_tag(scanner_data)
    tags = [identity]
    tags.extend(f"intent:{intent}" for intent in intents)
    tags.append("intensity:low")
    tags.append("response:monitor")

    policy_tags = document.get("policy_tags", [])
    existing = document.get("taxonomy", {}).get("tags", [])
    tags.extend(policy_tags)
    tags.extend(existing)

    return {
        "tags": list(dict.fromkeys(tags)),
        "identity": identity,
        "intents": intents,
        "intensity": "low",
        "response": "monitor",
    }
