"""Campaign profiling and threat actor attribution."""

from __future__ import annotations

from threat_intel.lookups import find_related_iocs

def build_campaign_profile(ioc: str, ioc_type: str) -> dict:
    related_data = find_related_iocs(ioc, ioc_type)

    malware_families = related_data.get("malware_families", [])
    related_ips = related_data.get("related_ips", [])
    related_domains = related_data.get("related_domains", [])
    related_hashes = related_data.get("related_hashes", [])

    campaign_name = "Unknown Campaign"
    campaign_type = "unknown"
    priority = "medium"
    confidence = 50

    if "Emotet" in malware_families:
        campaign_name = "Emotet Infrastructure Cluster"
        campaign_type = "botnet_c2"
        priority = "critical"
        confidence = 90

    elif "Trickbot" in malware_families:
        campaign_name = "Trickbot Infrastructure Cluster"
        campaign_type = "credential_theft"
        priority = "high"
        confidence = 85

    return {
        "campaign_name": campaign_name,
        "campaign_type": campaign_type,
        "campaign_confidence": confidence,
        "priority": priority,
        "malware_families": malware_families,
        "related_ips": related_ips,
        "related_domains": related_domains,
        "related_hashes": related_hashes,
    }

# ── Threat Actor Attribution ────────────────────────────────────────────────
def attribute_threat_actor(campaign_profile: dict) -> dict:
    malware_families = campaign_profile.get(
        "malware_families",
        []
    )

    actor = "Unknown"
    confidence = 0
    motivation = "Unknown"

    if "Emotet" in malware_families:
        actor = "TA505"
        confidence = 90
        motivation = "Financially Motivated Cybercrime"

    elif "Trickbot" in malware_families:
        actor = "Wizard Spider"
        confidence = 85
        motivation = "Financially Motivated Cybercrime"

    return {
        "threat_actor": actor,
        "attribution_confidence": confidence,
        "motivation": motivation,
    }
