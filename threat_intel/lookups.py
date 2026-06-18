"""IOC lookup backends used by enrichment and the Claude agent."""

from __future__ import annotations

import os

import requests


def lookup_ip_reputation(ip_address: str) -> dict:
    ip_database = {
        "203.0.113.42": {
            "ip": "203.0.113.42",
            "country": "Russia",
            "city": "Saint Petersburg",
            "isp": "MnogoByte LLC",
            "abuse_confidence_score": 87,
            "total_reports": 1243,
            "last_reported": "2026-03-10T14:22:00Z",
            "threat_types": ["botnet_c2", "malware_distribution", "brute_force"],
            "known_malware_associations": ["Emotet", "Trickbot"],
            "open_ports": [443, 8080, 4444],
            "is_known_proxy": True,
            "tags": ["banking-trojan-c2", "spam-source"],
        },
        "198.51.100.17": {
            "ip": "198.51.100.17",
            "country": "China",
            "city": "Shanghai",
            "isp": "ChinaNet",
            "abuse_confidence_score": 94,
            "total_reports": 3891,
            "last_reported": "2026-03-12T09:15:00Z",
            "threat_types": ["apt_c2", "data_exfiltration", "scanning"],
            "known_malware_associations": ["PlugX", "ShadowPad"],
            "open_ports": [443, 8443, 53],
            "is_known_proxy": False,
            "tags": ["apt-infrastructure", "state-sponsored"],
        },
    }
    return ip_database.get(
        ip_address,
        {
            "ip": ip_address,
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "threat_types": [],
            "note": "No records found for this IP",
        },
    )

# ── Real API ────────────────────────────────────────
def lookup_ip_reputation_abuseipdb(ip_address: str) -> dict:
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return {
            "ip": ip_address,
            "source": "AbuseIPDB",
            "error": "Missing ABUSEIPDB_API_KEY in .env",
        }

    url = "https://api.abuseipdb.com/api/v2/check"

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90,
        "verbose": True,
    }

    headers = {
        "Accept": "application/json",
        "Key": api_key,
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=10,
        )

        response.raise_for_status()

        raw_data = response.json().get("data", {})

        return {
            "ip": raw_data.get("ipAddress", ip_address),
            "source": "AbuseIPDB",
            "abuse_confidence_score": raw_data.get("abuseConfidenceScore", 0),
            "total_reports": raw_data.get("totalReports", 0),
            "country_code": raw_data.get("countryCode"),
            "usage_type": raw_data.get("usageType"),
            "isp": raw_data.get("isp"),
            "domain": raw_data.get("domain"),
            "hostnames": raw_data.get("hostnames", []),
            "is_public": raw_data.get("isPublic"),
            "is_whitelisted": raw_data.get("isWhitelisted"),
            "last_reported": raw_data.get("lastReportedAt"),
            "report_categories": [
                report.get("categories", [])
                for report in raw_data.get("reports", [])
            ],
            "raw": raw_data,
        }

    except requests.exceptions.RequestException as error:
        return {
            "ip": ip_address,
            "source": "AbuseIPDB",
            "error": str(error),
        }


def lookup_file_hash(file_hash: str, hash_type: str) -> dict:
    hash_database = {
        "d131dd02c5e6eec4693d9a0698aff95c": {
            "hash": "d131dd02c5e6eec4693d9a0698aff95c",
            "hash_type": "md5",
            "detections": 58,
            "total_engines": 72,
            "detection_rate": "80.6%",
            "malware_family": "Emotet",
            "malware_type": "banking_trojan",
            "severity": "critical",
            "file_name": "update_service.dll",
            "first_seen": "2025-12-01T08:30:00Z",
            "last_seen": "2026-03-09T22:14:00Z",
            "tags": ["emotet", "epoch5", "banking-trojan", "dropper"],
            "behavior_summary": "Drops secondary payload via regsvr32, establishes persistence via scheduled task, communicates with C2 over HTTPS on non-standard ports",
            "contacted_ips": ["203.0.113.42", "203.0.113.88", "192.0.2.101"],
            "contacted_domains": ["update-service-cdn.ru", "cdn-api-gateway.cc"],
        },
    }
    if file_hash not in hash_database:

        print(
            f"[WARNING] Unknown hash requested: {file_hash}"
        )

        return {
            "error": "Hash not found",
            "hash": file_hash,
            "hash_type": hash_type
        }

    return hash_database[file_hash]


def lookup_domain(domain: str) -> dict:
    domain_database = {
        "secure-bankofamerica-login.com": {
            "domain": "secure-bankofamerica-login.com",
            "reputation_score": 98,
            "category": "phishing",
            "active": True,
            "registrar": "NameSilo LLC",
            "registration_date": "2026-02-28T00:00:00Z",
            "registrant_country": "Panama",
            "hosting_provider": "BulletProof Hosting Ltd",
            "targeted_brand": "Bank of America",
            "similar_domains_found": 12,
            "tags": ["phishing-kit", "credential-harvest", "typosquat"],
        },
        "update-service-cdn.ru": {
            "domain": "update-service-cdn.ru",
            "reputation_score": 91,
            "category": "malware",
            "active": True,
            "registrar": "REG.RU LLC",
            "hosting_provider": "MnogoByte LLC",
            "tags": ["emotet-c2", "malware-distribution"],
            "associated_malware": ["Emotet", "Trickbot"],
        },
    }
    return domain_database.get(
        domain,
        {
            "domain": domain,
            "reputation_score": 0,
            "category": "unknown",
            "note": "No records found for this domain",
        },
    )


def get_mitre_techniques(query: str) -> dict:
    mitre_mappings = {
        "command and control": {
            "techniques": [
                {"id": "T1071.001", "name": "Web Protocols", "tactic": "Command and Control"},
                {"id": "T1573.002", "name": "Asymmetric Cryptography", "tactic": "Command and Control"},
                {"id": "T1008", "name": "Fallback Channels", "tactic": "Command and Control"},
            ],
            "associated_groups": ["APT28", "APT29", "Lazarus Group", "Wizard Spider"],
            "detection_suggestions": [
                "Monitor for unusual outbound HTTPS to non-standard ports",
                "Track beaconing patterns in network flow data",
            ],
        },
        "credential theft": {
            "techniques": [
                {"id": "T1056.001", "name": "Keylogging", "tactic": "Collection"},
                {"id": "T1555.003", "name": "Credentials from Web Browsers", "tactic": "Credential Access"},
                {"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access"},
            ],
            "associated_groups": ["Trickbot operators", "Emotet operators", "FIN7"],
            "detection_suggestions": [
                "Monitor for LSASS access by unusual processes",
                "Deploy credential guard on endpoints",
            ],
        },
        "phishing": {
            "techniques": [
                {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"},
                {"id": "T1566.002", "name": "Spearphishing Link", "tactic": "Initial Access"},
            ],
            "associated_groups": ["APT28", "Lazarus Group", "TA505"],
            "detection_suggestions": [
                "Implement DMARC/DKIM/SPF for email authentication",
                "Monitor for newly registered look-alike domains",
            ],
        },
        "lateral movement": {
            "techniques": [
                {"id": "T1210", "name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
                {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
            ],
            "associated_groups": ["Wizard Spider", "FIN6", "Sandworm Team"],
            "detection_suggestions": [
                "Monitor for anomalous SMB traffic patterns",
                "Track authentication events across endpoints",
            ],
        },
        "reconnaissance": {
            "techniques": [
                {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
                {"id": "T1595.002", "name": "Vulnerability Scanning", "tactic": "Reconnaissance"},
            ],
            "associated_groups": ["Censys", "Shodan", "Palo Alto Cortex Xpanse"],
            "detection_suggestions": [
                "Track port scanning and service enumeration across honeypot sensors",
                "Correlate probe activity with known scanner infrastructure ranges",
            ],
        },
    }
    query_lower = query.lower()
    for key, mapping in mitre_mappings.items():
        if key in query_lower:
            return mapping
    # Fuzzy fallback
    for key, mapping in mitre_mappings.items():
        for word in key.split():
            if word in query_lower:
                return mapping
    return {
        "techniques": [],
        "note": "No MITRE mapping found. Try: 'command and control', 'credential theft', 'phishing', or 'lateral movement'.",
    }
def calculate_risk_score(data: dict) -> dict:

    score = 0

    # IP reputation
    abuse = data.get("abuse_confidence_score", 0)

    if abuse >= 90:
        score += 40
    elif abuse >= 70:
        score += 30
    elif abuse >= 40:
        score += 20

    # Malware detections
    detections = data.get("detections", 0)

    if detections >= 50:
        score += 40
    elif detections >= 20:
        score += 25
    elif detections > 0:
        score += 10

    # Known malware
    if data.get("malware_family", "Unknown") != "Unknown":
        score += 30

    # Threat types
    threat_count = len(data.get("threat_types", []))
    score += min(threat_count * 8, 25)

    # Domain reputation
    reputation = data.get("reputation_score", 0)

    if reputation >= 90:
        score += 50
    elif reputation >= 70:
        score += 35

    # Phishing domains deserve a boost
    if data.get("category") == "phishing":
        score += 30

    # Malware domains deserve a boost
    if data.get("category") == "malware":
        score += 25

    score = min(score, 100)

    if score >= 85:
        severity = "CRITICAL"
    elif score >= 65:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "score": score,
        "severity": severity
    }
def find_related_iocs(ioc: str, ioc_type: str) -> dict:
    related_database = {
        "203.0.113.42": {
            "ioc": "203.0.113.42",
            "ioc_type": "ip_address",
            "related_domains": ["update-service-cdn.ru"],
            "related_hashes": ["d131dd02c5e6eec4693d9a0698aff95c"],
            "related_ips": ["203.0.113.88"],
            "malware_families": ["Emotet", "Trickbot"],
            "relationship_summary": "IP is associated with Emotet/Trickbot C2 infrastructure and overlaps with malware delivery domains.",
        },
        "d131dd02c5e6eec4693d9a0698aff95c": {
            "ioc": "d131dd02c5e6eec4693d9a0698aff95c",
            "ioc_type": "file_hash",
            "related_domains": ["update-service-cdn.ru", "cdn-api-gateway.cc"],
            "related_ips": ["203.0.113.42", "203.0.113.88", "192.0.2.101"],
            "related_hashes": [],
            "malware_families": ["Emotet"],
            "relationship_summary": "File hash contacts multiple C2 infrastructure nodes and malware delivery domains.",
        },
        "update-service-cdn.ru": {
            "ioc": "update-service-cdn.ru",
            "ioc_type": "domain",
            "related_ips": ["203.0.113.42", "203.0.113.88"],
            "related_hashes": ["d131dd02c5e6eec4693d9a0698aff95c"],
            "related_domains": ["cdn-api-gateway.cc"],
            "malware_families": ["Emotet", "Trickbot"],
            "relationship_summary": "Domain resolves to known malicious C2 infrastructure and is linked to Emotet activity.",
        },
    }

    if ioc not in related_database:
        return {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "related_ips": [],
            "related_domains": [],
            "related_hashes": [],
            "malware_families": [],
            "relationship_summary": "No related indicators found.",
        }

    return related_database[ioc]

# ── STAGE 7: Known Scanner Classification Tool ──────────────────────────────────
# Scanner inventory lives in config/scanners/known_scanner_inventory.csv with optional
# per-client JSON overrides in config/clients/{client_id}_scanners.json.
# classify_known_scanner() and list_scanner_inventory() are in threat_intel.scanners.

# ── STAGE 8: IOC Timeline Tool ────────────────────────────────────────────────
# run_mock_agent("203.0.113.42", "ip_address")
# run_mock_agent("d131dd02c5e6eec4693d9a0698aff95c", "file_hash")
# run_mock_agent("secure-bankofamerica-login.com", "domain")


# ── IPv4/IPv6 Analyzer ────────────────────────────────────────────────

def analyze_ip_version(ip_address: str) -> dict:
    try:
        ip_obj = ipaddress.ip_address(ip_address)

        return {
            "ip": ip_address,
            "valid_ip": True,
            "ip_version": f"IPv{ip_obj.version}",
            "is_private": ip_obj.is_private,
            "is_global": ip_obj.is_global,
            "is_loopback": ip_obj.is_loopback,
            "is_multicast": ip_obj.is_multicast,
        }

    except ValueError:
        return {
            "ip": ip_address,
            "valid_ip": False,
            "ip_version": "unknown",
            "error": "Invalid IP address format",
        }

# ── Tor/VPN/proxy/hosting classifier ────────────────────────────────────────────────

def classify_anonymizer_network(ip_address: str) -> dict:
    anonymizer_database = {
        "185.220.101.1": {
            "ip": "185.220.101.1",
            "network_type": "tor_exit_node",
            "provider": "Tor Network",
            "risk_modifier": "high",
            "is_anonymizer": True,
            "notes": "Known Tor exit node. Not automatically malicious, but high risk for login attempts or abuse events.",
        },
        "45.134.26.12": {
            "ip": "45.134.26.12",
            "network_type": "commercial_vpn",
            "provider": "Common VPN Provider",
            "risk_modifier": "medium",
            "is_anonymizer": True,
            "notes": "Commercial VPN infrastructure often used for privacy but also abused by attackers.",
        },
        "185.234.216.55": {
            "ip": "185.234.216.55",
            "network_type": "bulletproof_hosting",
            "provider": "Suspicious Hosting Provider",
            "risk_modifier": "high",
            "is_anonymizer": False,
            "notes": "Hosting provider commonly associated with abuse-resistant infrastructure.",
        },
    }

    return anonymizer_database.get(
        ip_address,
        {
            "ip": ip_address,
            "network_type": "unknown",
            "provider": "unknown",
            "risk_modifier": "none",
            "is_anonymizer": False,
            "notes": "No anonymizer, VPN, Tor, or suspicious hosting match found.",
        },
    )

# ── GreyNoise ────────────────────────────────────────────────

def classify_greynoise(ip_address: str) -> dict:

    greynoise_database = {

        "198.235.24.10": {
            "classification": "benign_scanner",
            "noise_level": "high",
            "actor": "Palo Alto Cortex Xpanse",
            "recommendation": "Ignore unless exploit activity observed"
        },

        "203.0.113.42": {
            "classification": "malicious",
            "noise_level": "high",
            "actor": "Emotet Infrastructure",
            "recommendation": "Investigate immediately"
        },

        "45.134.26.12": {
            "classification": "suspicious",
            "noise_level": "medium",
            "actor": "VPN Infrastructure",
            "recommendation": "Monitor activity"
        }
    }

    return greynoise_database.get(
        ip_address,
        {
            "classification": "unknown",
            "noise_level": "unknown",
            "actor": "unknown",
            "recommendation": "No GreyNoise context available"
        }
    )

# ── Timeline Counts ────────────────────────────────────────────────

def lookup_ioc_timeline(ioc: str, ioc_type: str) -> dict:

    timeline_database = {

        "203.0.113.42": {
            "first_seen": "2025-12-01",
            "last_seen": "2026-03-10",
            "observation_count": 1243,
            "days_active": 99,
            "trend": "increasing"
        },

        "update-service-cdn.ru": {
            "first_seen": "2026-01-14",
            "last_seen": "2026-03-10",
            "observation_count": 488,
            "days_active": 55,
            "trend": "stable"
        }
    }

    return timeline_database.get(
        ioc,
        {
            "first_seen": "unknown",
            "last_seen": "unknown",
            "observation_count": 0,
            "days_active": 0,
            "trend": "unknown"
        }
    )
