"""Incident clustering, MITRE mapping, and prioritization."""

from __future__ import annotations

from threat_intel.lookups import get_mitre_techniques

def summarize_enriched_batch(enriched_documents: list) -> dict:
    summary = {
        "total_events": len(enriched_documents),
        "severity_counts": {},
        "classification_counts": {},
        "cache_counts": {},
        "top_source_ips": {},
        "critical_events": [],
    }

    for doc in enriched_documents:
        severity = doc.get("threat", {}).get("severity", "UNKNOWN")
        classification = doc.get("investigation", {}).get("classification", "unknown")
        cache_status = doc.get("elastic_metadata", {}).get("cache_status", "unknown")
        source_ip = doc.get("source", {}).get("ip")

        summary["severity_counts"][severity] = (
            summary["severity_counts"].get(severity, 0) + 1
        )

        summary["classification_counts"][classification] = (
            summary["classification_counts"].get(classification, 0) + 1
        )

        summary["cache_counts"][cache_status] = (
            summary["cache_counts"].get(cache_status, 0) + 1
        )

        if source_ip:
            summary["top_source_ips"][source_ip] = (
                summary["top_source_ips"].get(source_ip, 0) + 1
            )

        if severity == "CRITICAL":
            summary["critical_events"].append({
                "source_ip": source_ip,
                "destination_port": doc.get("destination", {}).get("port"),
                "attack_type": doc.get("stingar", {}).get("attack_type"),
                "campaign": doc.get("campaign", {}).get("name"),
                "threat_actor": doc.get("threat_actor", {}).get("name"),
            })

    return summary

# ── Cluster Incidents ────────────────────────────────────────────────

def get_cluster_recommended_action(severity: str) -> str:

    if severity == "CRITICAL":
        return (
            "Escalate to incident response, block source IP, "
            "and investigate related IOCs."
        )

    elif severity == "HIGH":
        return (
            "Prioritize analyst review and search for related activity."
        )

    elif severity == "MEDIUM":
        return (
            "Monitor and review supporting telemetry."
        )

    elif severity == "LOW":
        return (
            "Track for recurrence."
        )

    return (
        "Suppress or monitor as informational activity."
    )


HONEYPOT_ATTACK_TYPE_MITRE = {
    "ssh_bruteforce": {
        "techniques": [
            {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
            {"id": "T1021.004", "name": "SSH", "tactic": "Lateral Movement"},
        ],
        "detection_suggestions": [
            "Alert on repeated failed SSH authentication attempts from a single source IP",
            "Monitor for successful SSH logins following brute-force patterns",
        ],
    },
    "telnet_probe": {
        "techniques": [
            {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
            {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        ],
        "detection_suggestions": [
            "Monitor for Telnet connection attempts on deprecated or unexpected services",
            "Correlate Telnet probes with credential-spray activity across sensors",
        ],
    },
    "service_probe": {
        "techniques": [
            {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
            {"id": "T1595.002", "name": "Vulnerability Scanning", "tactic": "Reconnaissance"},
        ],
        "detection_suggestions": [
            "Track port scanning and service enumeration across honeypot sensors",
            "Correlate probe activity with known scanner infrastructure ranges",
        ],
    },
}

CAMPAIGN_TYPE_MITRE_QUERY = {
    "botnet_c2": "command and control",
    "credential_theft": "credential theft",
    "unknown": "reconnaissance",
}

MALWARE_FAMILY_MITRE_QUERY = {
    "Emotet": "command and control",
    "Trickbot": "credential theft",
}


def build_cluster_mitre_attack(cluster: dict) -> dict:
    """
    Map an incident cluster to MITRE ATT&CK techniques, tactics,
    and detection suggestions using attack types, campaign context,
    and malware families observed in the cluster.
    """
    techniques_by_id = {}
    detection_suggestions = []
    mapping_sources = []

    for attack_type in cluster.get("attack_types", []):
        attack_mapping = HONEYPOT_ATTACK_TYPE_MITRE.get(attack_type)
        if not attack_mapping:
            continue

        mapping_sources.append(f"attack_type:{attack_type}")

        for technique in attack_mapping.get("techniques", []):
            techniques_by_id[technique["id"]] = technique

        detection_suggestions.extend(
            attack_mapping.get("detection_suggestions", [])
        )

    campaign_type = cluster.get("campaign_type", "unknown")
    campaign_query = CAMPAIGN_TYPE_MITRE_QUERY.get(
        campaign_type,
        "reconnaissance",
    )
    campaign_mapping = get_mitre_techniques(campaign_query)

    if campaign_mapping.get("techniques"):
        mapping_sources.append(f"campaign_type:{campaign_type}")

        for technique in campaign_mapping["techniques"]:
            techniques_by_id[technique["id"]] = technique

        detection_suggestions.extend(
            campaign_mapping.get("detection_suggestions", [])
        )

    for malware_family in cluster.get("malware_families", []):
        malware_query = MALWARE_FAMILY_MITRE_QUERY.get(malware_family)
        if not malware_query:
            continue

        malware_mapping = get_mitre_techniques(malware_query)
        if not malware_mapping.get("techniques"):
            continue

        mapping_sources.append(f"malware_family:{malware_family}")

        for technique in malware_mapping["techniques"]:
            techniques_by_id[technique["id"]] = technique

        detection_suggestions.extend(
            malware_mapping.get("detection_suggestions", [])
        )

    techniques = list(techniques_by_id.values())
    tactics = sorted({technique["tactic"] for technique in techniques})

    return {
        "techniques": techniques,
        "tactics": tactics,
        "detection_suggestions": list(dict.fromkeys(detection_suggestions)),
        "mapping_sources": mapping_sources,
    }


def build_incident_clusters(enriched_documents: list) -> list:
    """
    Group related enriched events into incidents.
    """

    clusters = {}

    for doc in enriched_documents:

        source_ip = doc["source"]["ip"]

        campaign = doc["campaign"]["name"]

        actor = doc["threat_actor"]["name"]

        cluster_key = f"{source_ip}|{campaign}"

        if cluster_key not in clusters:

            recurrence = detect_recurring_attacker(source_ip)

            clusters[cluster_key] = {
                "incident_id": f"incident-{abs(hash(cluster_key)) % 100000}",
                "source_ip": source_ip,
                "campaign": campaign,
                "campaign_type": doc["campaign"].get("type", "unknown"),
                "threat_actor": actor,
                "severity": doc["threat"]["severity"],
                "recommended_action": get_cluster_recommended_action(
                    doc["threat"]["severity"]
                ),
                "recurrence": recurrence,
                "event_count": 0,
                "attack_types": set(),
                "destination_ports": set(),
                "malware_families": set(),
            }

        cluster = clusters[cluster_key]

        cluster["event_count"] += 1

        cluster["attack_types"].add(
            doc["stingar"]["attack_type"]
        )

        cluster["destination_ports"].add(
            doc["destination"]["port"]
        )

        for family in doc["campaign"].get("malware_families", []):
            cluster["malware_families"].add(family)

    results = []

    for cluster in clusters.values():

        cluster["attack_types"] = sorted(
            list(cluster["attack_types"])
        )

        cluster["destination_ports"] = sorted(
            list(cluster["destination_ports"])
        )

        cluster["malware_families"] = sorted(
            list(cluster["malware_families"])
        )

        cluster["mitre_attack"] = build_cluster_mitre_attack(cluster)

        results.append(cluster)

    from threat_intel.taxonomy import attach_taxonomy_to_clusters

    return attach_taxonomy_to_clusters(results)

# ── Priority Queue ────────────────────────────────────────────────

def prioritize_incidents(incident_clusters: list) -> list:
    """
    Sort incidents by importance.
    """

    severity_weights = {
        "CRITICAL": 100,
        "HIGH": 75,
        "MEDIUM": 50,
        "LOW": 25,
        "INFORMATIONAL": 0,
    }

    for incident in incident_clusters:

        severity = incident.get(
            "severity",
            "INFORMATIONAL"
        )

        event_count = incident.get(
            "event_count",
            1
        )

        recurrence = incident.get("recurrence") or {}

        historical_incidents = recurrence.get(
            "historical_incidents",
            0
        )

        trend = recurrence.get(
            "trend",
            "unknown"
        )

        recurrence_bonus = min(
            historical_incidents * 2,
            30
        )

        trend_bonus = 15 if trend == "increasing" else 0

        score = (
            severity_weights.get(severity, 0)
            + (event_count * 5)
            + recurrence_bonus
            + trend_bonus
        )

        incident["priority_score"] = score

    return sorted(
        incident_clusters,
        key=lambda x: x["priority_score"],
        reverse=True
    )

 #── Labels Recurring Attacker ────────────────────────────────────────────────
def detect_recurring_attacker(ip_address: str) -> dict:

    attacker_history_db = {

        "203.0.113.42": {
            "first_seen": "2025-11-15",
            "last_seen": "2026-06-10",
            "historical_events": 347,
            "historical_incidents": 28,
            "trend": "increasing",
        },

        "198.235.24.10": {
            "first_seen": "2026-01-01",
            "last_seen": "2026-06-10",
            "historical_events": 5200,
            "historical_incidents": 0,
            "trend": "stable",
        }
    }

    history = attacker_history_db.get(ip_address)

    if not history:
        return {
            "recurring_attacker": False,
            "historical_events": 0,
            "historical_incidents": 0,
            "trend": "unknown",
            "recommendation": "Monitor for future activity."
        }

    recurring = history["historical_events"] >= 10

    has_prior_incidents = history["historical_incidents"] > 0

    if has_prior_incidents and history["trend"] == "increasing":
        recommendation = "Escalate recurring attacker activity."

    elif has_prior_incidents:
        recommendation = "Review recurring incident history."

    elif recurring:
        recommendation = "Recurring source activity observed; monitor for suspicious behavior."

    else:
        recommendation = "Monitor."

    return {
        "recurring_source": recurring,
        "has_prior_incidents": has_prior_incidents,
        "historical_events": history["historical_events"],
        "historical_incidents": history["historical_incidents"],
        "trend": history["trend"],
        "recommendation": recommendation,
    }
