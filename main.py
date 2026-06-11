import ipaddress
import json
import anthropic
import os
import requests

# Hardcode the key directly for now
from dotenv import load_dotenv
from datetime import datetime, timezone
import os

STANDARD_IOC_TYPES = {
    "ip": "ip_address",
    "ipv4": "ip_address",
    "ipv6": "ip_address",
    "ip_address": "ip_address",
    "domain": "domain",
    "url": "url",
    "hash": "file_hash",
    "md5": "file_hash",
    "sha1": "file_hash",
    "sha256": "file_hash",
    "file_hash": "file_hash",
}


def standardize_ioc_type(ioc_type: str) -> str:
    normalized = ioc_type.lower().strip()
    return STANDARD_IOC_TYPES.get(normalized, "unknown")

load_dotenv()

client = anthropic.Anthropic(
    api_key=os.getenv("ANTHROPIC_API_KEY")
)
MODEL_NAME = "claude-sonnet-4-6"

# response = client.messages.create(
#     model="claude-sonnet-4-6",
#     max_tokens=100,
#     messages=[{"role": "user", "content": "Say hello in one sentence."}]
# )

# print(response.content[0].text)

# ── STAGE 2: Tool Definitions ──────────────────────────────────────────
tools = [
    {
        "name": "lookup_ip_reputation",
        "description": "Query IP reputation database to get geolocation, ISP information, abuse history, open ports, and known malicious associations for an IP address.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IPv4 or IPv6 address to investigate.",
                }
            },
            "required": ["ip_address"],
        },
    },

    {
        "name": "lookup_ip_reputation_abuseipdb",
        "description": "Query the real AbuseIPDB API for IP reputation, abuse confidence score, total reports, geolocation, ISP, hostnames, and recent abuse report context.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IPv4 or IPv6 address to check in AbuseIPDB.",
                }
            },
            "required": ["ip_address"],
        },
    },
    {
        "name": "lookup_file_hash",
        "description": "Query file reputation service with a cryptographic hash. Returns detection ratio across antivirus engines, malware family classification, and behavioral summary.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_hash": {
                    "type": "string",
                    "description": "The MD5, SHA1, or SHA256 hash of the suspicious file.",
                },
                "hash_type": {
                    "type": "string",
                    "enum": ["md5", "sha1", "sha256"],
                    "description": "The type of hash provided.",
                },
            },
            "required": ["file_hash", "hash_type"],
        },
    },
    {
        "name": "lookup_domain",
        "description": "Investigate a domain's reputation including registration details, DNS records, hosting provider, and threat categorization.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "The domain name to investigate (e.g., example.com).",
                }
            },
            "required": ["domain"],
        },
    },
    {
        "name": "get_mitre_techniques",
        "description": "Map observed behaviors, malware families, or attack patterns to the MITRE ATT&CK framework. Returns matching technique IDs, tactic categories, and detection recommendations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Description of the behavior or malware family to map (e.g., 'command and control beaconing', 'credential theft').",
                }
            },
            "required": ["query"],
        },
    },
    {
        "name": "find_related_iocs",
        "description": "Find indicators related to a given IOC, including connected IPs, domains, file hashes, malware families, and infrastructure relationships. Useful for pivoting from one indicator to broader campaign infrastructure.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ioc": {
                    "type": "string",
                    "description": "The indicator to pivot from, such as an IP address, domain, or file hash.",
                },
                "ioc_type": {
                    "type": "string",
                    "enum": ["ip_address", "domain", "file_hash"],
                    "description": "The type of IOC being investigated.",
                },
            },
            "required": ["ioc", "ioc_type"],
        },
    },

    {
        "name": "classify_known_scanner",
        "description": "Determine whether an IP address belongs to a known internet scanner or security research organization such as Censys, Shodan, Palo Alto Cortex Xpanse, or other benign scanning infrastructure.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IP address to classify.",
                }
            },
            "required": ["ip_address"],
        },
    },

    {
        "name": "lookup_ioc_timeline",
        "description": "Look up first seen, last seen, activity duration, and trend information for an IOC. Useful for determining whether an indicator is new, old, active, recurring, or increasing in activity.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ioc": {
                    "type": "string",
                    "description": "The indicator to look up, such as an IP address, domain, or file hash.",
                },
                "ioc_type": {
                    "type": "string",
                    "enum": ["ip_address", "domain", "file_hash"],
                    "description": "The type of IOC being investigated.",
                },
            },
            "required": ["ioc", "ioc_type"],
        },
    },

    {
        "name": "classify_greynoise",
        "description": "Classify internet background noise versus malicious infrastructure using a GreyNoise-style classification.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IP address to classify.",
                }
            },
            "required": ["ip_address"],
        },
    },

    {
        "name": "classify_anonymizer_network",
        "description": "Detect Tor, VPN, proxy, and suspicious hosting providers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IP address to classify.",
                }
            },
            "required": ["ip_address"],
        },
    },

    {
        "name": "analyze_ip_version",
        "description": "Analyze whether an IP address is IPv4 or IPv6 and return basic IP properties.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IP address to analyze.",
                }
            },
            "required": ["ip_address"],
        },
    },

    {
        "name": "calculate_enriched_severity_tool",
        "description": "Calculate enriched severity, confidence, threat score, and risk factors for an IP address by combining reputation, scanner classification, anonymizer detection, GreyNoise-style classification, and timeline counts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IP address to calculate enriched severity for.",
                }
            },
            "required": ["ip_address"],
        },
    },

    {
        "name": "classify_investigation_outcome_tool",
        "description": "Classify the investigation outcome for an IP address as known scanner, benign internet noise, active reconnaissance, anonymized traffic, suspicious hosting, malicious infrastructure, or confirmed C2 by combining reputation, scanner attribution, anonymizer context, GreyNoise-style classification, and timeline data.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IP address to classify.",
                }
            },
            "required": ["ip_address"],
        },
    },
    {
    "name": "build_intelligence_summary_tool",
    "description": "Build a full intelligence summary for an IP address, including enriched severity, investigation classification, campaign profile, and threat actor attribution.",
    "input_schema": {
        "type": "object",
        "properties": {
            "ip_address": {
                "type": "string",
                "description": "The IP address to summarize.",
            }
        },
        "required": ["ip_address"],
    },
},
]

print(f"Defined {len(tools)} tools: {[t['name'] for t in tools]}")

# ── STAGE 3: Simulated Backends ────────────────────────────────────────

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


print("Backends ready.")

# ── Risk Scoring Engine ────────────────────────────────────────────────

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

# ── Final Scoring ────────────────────────────────────────────────

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

# ── Classificaiton Enrichment ────────────────────────────────────────────────

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

# ── Broadens IP Scheme ────────────────────────────────────────────────

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

# ── Full Intelligence Summary ────────────────────────────────────────────────

def build_intelligence_summary(
    ip_address: str
) -> dict:

    severity = calculate_enriched_severity_tool(
        ip_address
    )

    investigation = classify_investigation_outcome_tool(
        ip_address
    )

    campaign = build_campaign_profile(
        ip_address,
        "ip_address"
    )

    actor = attribute_threat_actor(
        campaign
    )

    return {
        "indicator": ip_address,
        "severity": severity,
        "investigation": investigation,
        "campaign": campaign,
        "threat_actor": actor,
    }

# ── Convert to Elastic Document ────────────────────────────────────────────────
def convert_to_elastic_document(
    honeypot_event: dict,
    intelligence_summary: dict
) -> dict:
    """
    Converts a STINGAR honeypot event + enrichment output
    into an Elasticsearch-ready document.
    """

    severity = intelligence_summary.get("severity", {})
    investigation = intelligence_summary.get("investigation", {})
    campaign = intelligence_summary.get("campaign", {})
    threat_actor = intelligence_summary.get("threat_actor", {})

    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),

        "event": {
            "source": "stingar_honeypot",
            "type": "honeypot_attack",
            "original": honeypot_event,
        },

        "source": {
            "ip": honeypot_event.get("source_ip"),
            "port": honeypot_event.get("source_port"),
        },

        "destination": {
            "ip": honeypot_event.get("destination_ip"),
            "port": honeypot_event.get("destination_port"),
        },

        "network": {
            "protocol": honeypot_event.get("protocol"),
            "transport": honeypot_event.get("transport", "tcp"),
        },

        "stingar": {
            "sensor_id": honeypot_event.get("sensor_id"),
            "honeypot_type": honeypot_event.get("honeypot_type"),
            "attack_type": honeypot_event.get("attack_type"),
        },

        "threat": {
            "indicator": {
                "ip": intelligence_summary.get("indicator"),
                "type": "ip_address",
            },
            "severity": severity.get("severity"),
            "threat_score": severity.get("threat_score"),
            "confidence_score": severity.get("confidence_score"),
            "risk_factors": severity.get("risk_factors", []),
        },

        "investigation": {
            "classification": investigation.get("investigation_classification"),
            "category": investigation.get("category"),
            "priority": investigation.get("priority"),
            "reasons": investigation.get("reasons", []),
        },

        "campaign": {
            "name": campaign.get("campaign_name"),
            "type": campaign.get("campaign_type"),
            "confidence": campaign.get("campaign_confidence"),
            "priority": campaign.get("priority"),
            "malware_families": campaign.get("malware_families", []),
            "related_ips": campaign.get("related_ips", []),
            "related_domains": campaign.get("related_domains", []),
            "related_hashes": campaign.get("related_hashes", []),
        },

        "threat_actor": {
            "name": threat_actor.get("threat_actor"),
            "confidence": threat_actor.get("attribution_confidence"),
            "motivation": threat_actor.get("motivation"),
        },

        "elastic_metadata": {
            "document_type": "stingar_enriched_honeypot_event",
            "pipeline": "threat_intelligence_enrichment",
            "version": "1.0",
        },
    }

# ── Actual Threat Report ────────────────────────────────────────────────

def generate_threat_report(ioc: str, data: dict) -> str:

    risk = calculate_risk_score(data)

    report = []

    report.append("=" * 60)
    report.append("THREAT INTELLIGENCE REPORT")
    report.append("=" * 60)

    report.append(f"IOC: {ioc}")
    report.append(f"Risk Score: {risk['score']}/100")
    report.append(f"Severity: {risk['severity']}")
    report.append("")

    # Location / ownership
    if "country" in data:
        report.append(f"Country: {data['country']}")

    if "city" in data:
        report.append(f"City: {data['city']}")

    if "isp" in data:
        report.append(f"ISP: {data['isp']}")

    # Malware info
    if "malware_family" in data:
        report.append(f"Malware Family: {data['malware_family']}")

    if "malware_type" in data:
        report.append(f"Malware Type: {data['malware_type']}")

    # Domain info
    if "category" in data:
        report.append(f"Category: {data['category']}")

    report.append("")

    if "threat_types" in data and data["threat_types"]:
        report.append("Threat Types:")
        for threat in data["threat_types"]:
            report.append(f"  - {threat}")

    if "known_malware_associations" in data:
        report.append("")
        report.append("Associated Malware:")
        for malware in data["known_malware_associations"]:
            report.append(f"  - {malware}")

    if "tags" in data:
        report.append("")
        report.append("Tags:")
        for tag in data["tags"]:
            report.append(f"  - {tag}")

    report.append("")
    if "contacted_ips" in data and data["contacted_ips"]:
        report.append("")
        report.append("Contacted IPs:")
        for ip in data["contacted_ips"]:
            report.append(f"  - {ip}")

    if "contacted_domains" in data and data["contacted_domains"]:
        report.append("")
        report.append("Contacted Domains:")
        for domain in data["contacted_domains"]:
            report.append(f"  - {domain}")

    report.append("")
    report.append("Recommended Actions:")

    if risk["severity"] == "CRITICAL":
        report.append("- Block immediately")
        report.append("- Isolate affected hosts")
        report.append("- Begin incident response")

    elif risk["severity"] == "HIGH":
        report.append("- Investigate immediately")
        report.append("- Search environment for related indicators")
        report.append("- Increase monitoring")

    elif risk["severity"] == "MEDIUM":
        report.append("- Review logs")
        report.append("- Monitor activity")
        report.append("- Search for related indicators")

    else:
        report.append("- Record indicator")
        report.append("- Continue monitoring")

    return "\n".join(report)

def export_report_json(ioc: str, ioc_type: str, data: dict) -> dict:
    risk = calculate_risk_score(data)

    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "risk_score": risk["score"],
        "severity": risk["severity"],
        "malware_family": data.get("malware_family"),
        "malware_type": data.get("malware_type"),
        "category": data.get("category"),
        "tags": data.get("tags", []),
        "contacted_ips": data.get("contacted_ips", []),
        "contacted_domains": data.get("contacted_domains", []),
        "recommended_actions": get_recommended_actions(risk["severity"]),
    }


def get_recommended_actions(severity: str) -> list:
    if severity == "CRITICAL":
        return [
            "Block immediately",
            "Isolate affected hosts",
            "Begin incident response",
        ]
    elif severity == "HIGH":
        return [
            "Investigate immediately",
            "Search environment for related indicators",
            "Increase monitoring",
        ]
    elif severity == "MEDIUM":
        return [
            "Review logs",
            "Monitor activity",
            "Search for related indicators",
        ]
    else:
        return [
            "Record indicator",
            "Continue monitoring",
        ]

def build_relationship_graph(hash_data: dict):

    malware_family = hash_data.get("malware_family")

    mitre_data = {}

    if malware_family == "Emotet":
        mitre_data = get_mitre_techniques(
            "command and control"
        )

    graph = {
        "root": hash_data["hash"],
        "malware_family": malware_family,
        "contacted_ips": hash_data.get("contacted_ips", []),
        "contacted_domains": hash_data.get("contacted_domains", []),
        "mitre_techniques": mitre_data.get("techniques", [])
    }

    return graph

def display_relationship_graph(graph):

    print("\n")
    print("=" * 60)
    print("IOC RELATIONSHIP GRAPH")
    print("=" * 60)

    print(f"Hash: {graph['root']}")

    if graph["malware_family"]:
        print(f" ├── Malware: {graph['malware_family']}")


    for technique in graph["mitre_techniques"]:
        print(
            f" ├── MITRE: "
            f"{technique['id']} "
            f"({technique['name']})"
        )

    for ip in graph["contacted_ips"]:
        print(f" ├── IP: {ip}")

    for domain in graph["contacted_domains"]:
        print(f" ├── Domain: {domain}")


# ── STAGE 4: Agent Loop ────────────────────────────────────────────────
SYSTEM_PROMPT = """

Important:
- For IP address investigations, call build_intelligence_summary_tool first.
- If build_intelligence_summary_tool returns a complete summary, do not call any other tools.
- Only call additional tools if the summary is missing critical information.

You are a senior cyber threat intelligence analyst.

When investigating an IOC, use the available tools to enrich it efficiently.

Tool budget:
- For IP investigations, use at most 8 total tool calls.
- After calculate_enriched_severity_tool is called, do not call any more tools.
- If enriched severity, reputation, scanner classification, GreyNoise classification, timeline, and related IOCs are available, stop and write the final report.
- Do not call get_mitre_techniques more than once per investigation.

For IP addresses:
- Use build_intelligence_summary_tool as the primary enrichment workflow.
- Do not manually call individual IP enrichment tools unless the summary is incomplete.

For domains:
- Check domain reputation.
- Check related IOCs.
- Check timeline data.
- Map relevant behaviors to MITRE ATT&CK.

For file hashes:
- Check file hash reputation.
- Investigate only related IPs or domains returned by tools.
- Map malware behaviors to MITRE ATT&CK.
- Do not invent hashes, domains, or IPs.

Rules:
- Do not call the same tool repeatedly for similar information.
- Do not invent indicators.
- Only investigate indicators explicitly provided by the user or returned by tools.
- Distinguish malicious infrastructure from known benign scanner traffic.
- Treat Tor/VPN/proxy traffic as context, not automatic proof of maliciousness.
- Produce concise analyst-ready reports with severity, confidence, evidence, and recommended actions.
- Keep the final report under 600 words.
- Use concise bullet points instead of long narrative explanations.
"""

MAX_TURNS = 4 # prevents runaway loops and runaway costs


def process_tool_call(tool_name: str, tool_input: dict) -> str:
    """Routes Claude's tool requests to the right backend function."""
    handlers = {
        "lookup_ip_reputation": lambda inp: lookup_ip_reputation(inp["ip_address"]),
        "lookup_ip_reputation_abuseipdb": lambda inp: lookup_ip_reputation_abuseipdb(inp["ip_address"]),
        "lookup_file_hash": lambda inp: lookup_file_hash(inp["file_hash"], inp["hash_type"]),
        "lookup_domain": lambda inp: lookup_domain(inp["domain"]),
        "get_mitre_techniques": lambda inp: get_mitre_techniques(inp["query"]),
        "find_related_iocs": lambda inp: find_related_iocs(inp["ioc"], inp["ioc_type"]),
        "classify_known_scanner": lambda inp: classify_known_scanner(inp["ip_address"]),
        "lookup_ioc_timeline": lambda inp: lookup_ioc_timeline(inp["ioc"], inp["ioc_type"]),
        "analyze_ip_version": lambda inp: analyze_ip_version(inp["ip_address"]),
        "classify_greynoise": lambda inp: classify_greynoise(inp["ip_address"]),
        "classify_anonymizer_network": lambda inp: classify_anonymizer_network(inp["ip_address"]),
        "calculate_enriched_severity_tool": lambda inp: calculate_enriched_severity_tool(inp["ip_address"]),
        "classify_investigation_outcome_tool": lambda inp: classify_investigation_outcome_tool(inp["ip_address"]),
        "build_intelligence_summary_tool": lambda inp: build_intelligence_summary(inp["ip_address"]),
    }
    handler = handlers.get(tool_name)
    if handler is None:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})
    return json.dumps(handler(tool_input), indent=2)


def run_threat_intel_agent(ioc: str, ioc_type: str) -> tuple: #fix api key to run this 
    """
    The core agent loop.
    Keeps running until Claude says it's done (stop_reason == 'end_turn')
    or we hit MAX_TURNS.
    """
    user_message = (
        f"Investigate this indicator of compromise and provide a threat assessment:\n"
        f"  IOC: {ioc}\n"
        f"  Type: {ioc_type}\n\n"
        f"Use the fewest relevant tools. For IP addresses, call calculate_enriched_severity_tool once enough context is available, then stop tool use and write the final report. "
        f"Provide severity, confidence score, evidence, and recommended response actions. "
        f"Keep the report under 500 words."
    )

    messages = [{"role": "user", "content": user_message}]
    tool_calls_made = []

    for turn in range(MAX_TURNS):
        print(f"  [Turn {turn + 1}] Calling Claude...")

        response = client.messages.create( #fix api key to run this 
            model=MODEL_NAME,
            max_tokens=3000,
            system=SYSTEM_PROMPT,
            tools=tools,
            messages=messages,
        )

        # extract the final text response
        if response.stop_reason == "end_turn":
            final_text = next(
                (block.text for block in response.content if hasattr(block, "text")),
                "No analysis generated.",
            )
            return final_text, tool_calls_made

        # use tools
        if response.stop_reason == "tool_use":

            # Add response to the conversation history
            messages.append({"role": "assistant", "content": response.content})

            # Process every tool call requested
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    print(f"    -> Tool: {block.name}({json.dumps(block.input)})")
                    tool_calls_made.append({"tool": block.name, "input": block.input})

                    if block.name == "calculate_enriched_severity_tool":
                        print("    -> Enriched severity calculated. Agent should stop after this turn.")

                    result = process_tool_call(block.name, block.input)

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result,
                    })

            # Feed the tool results back so it can continue reasoning
            messages.append({"role": "user", "content": tool_results})

        else:
            return f"Unexpected stop reason: {response.stop_reason}", tool_calls_made

    return f"Hit MAX_TURNS limit ({MAX_TURNS}) without finishing.", tool_calls_made


print("Agent loop ready.")

#temp testing block
# print("\nTesting IP Lookup")
# print(json.dumps(
#     lookup_ip_reputation("203.0.113.42"),
#     indent=2
# ))

# print("\nTesting Hash Lookup")
# print(json.dumps(
#     lookup_file_hash(
#         "d131dd02c5e6eec4693d9a0698aff95c",
#         "md5"
#     ),
#     indent=2
# ))

# print("\nTesting Domain Lookup")
# print(json.dumps(
#     lookup_domain("update-service-cdn.ru"),
#     indent=2
# ))

# print("\nTesting MITRE Lookup")
# print(json.dumps(
#     get_mitre_techniques("command and control"),
#     indent=2
# ))

# ── STAGE 5: Run Sample IOCs ───────────────────────────────────────────

# sample_iocs = [ 
#     {
#         "description": "Suspicious IP flagged by firewall for outbound C2 beaconing",
#         "ioc": "203.0.113.42",
#         "ioc_type": "ip_address",
#     },
#     {
#         "description": "File hash from endpoint detection alert",
#         "ioc": "d131dd02c5e6eec4693d9a0698aff95c",
#         "ioc_type": "file_hash",
#     },
#     {
#         "description": "Domain found in phishing email",
#         "ioc": "secure-bankofamerica-login.com",
#         "ioc_type": "domain",
#     },
# ]

# for test in sample_iocs:
#     print("\n" + "=" * 70)
#     print(test["description"])
#     print(f"IOC: {test['ioc']}")
#     print(f"Type: {test['ioc_type']}")
#     print("=" * 70)

#     analysis, tool_calls = run_threat_intel_agent(
#         test["ioc"],
#         test["ioc_type"]
#     )

#     print(f"\n--- Agent queried {len(tool_calls)} tool(s) ---")
#     print("\nAnalysis:")
#     print(analysis) #final threat report 


# ── STAGE 5: No-API Mock Agent Runner ──────────────────────────────────

#comment this out after api is ready and comment out actual stage 5 
def run_mock_agent(ioc: str, ioc_type: str):
    print("\n" + "=" * 70)
    print(f"MOCK INVESTIGATION")
    print(f"IOC: {ioc}")
    print(f"Type: {ioc_type}")
    print("=" * 70)

    if ioc_type == "ip_address":
        ip_result = lookup_ip_reputation(ioc)
        print("\n[1] IP Reputation Result:")
        print(json.dumps(ip_result, indent=2))

        malware_list = ip_result.get("known_malware_associations", [])
        threat_types = ip_result.get("threat_types", [])

        if malware_list or threat_types:
            print("\n[2] MITRE ATT&CK Mapping:")
            mitre_result = get_mitre_techniques("command and control credential theft")
            print(json.dumps(mitre_result, indent=2))

    elif ioc_type == "file_hash":
        hash_result = lookup_file_hash(ioc, "md5")
        print("\n[1] File Hash Reputation Result:")
        print(json.dumps(hash_result, indent=2))

        print("\n[2] Contacted IP Lookups:")
        for ip in hash_result.get("contacted_ips", []):
            print(f"\n--- {ip} ---")
            print(json.dumps(lookup_ip_reputation(ip), indent=2))

        print("\n[3] Contacted Domain Lookups:")
        for domain in hash_result.get("contacted_domains", []):
            print(f"\n--- {domain} ---")
            print(json.dumps(lookup_domain(domain), indent=2))

        print("\n[4] MITRE ATT&CK Mapping:")
        mitre_result = get_mitre_techniques("command and control credential theft lateral movement")
        print(json.dumps(mitre_result, indent=2))

    elif ioc_type == "domain":
        domain_result = lookup_domain(ioc)
        print("\n[1] Domain Reputation Result:")
        print(json.dumps(domain_result, indent=2))

        category = domain_result.get("category", "")

        if category == "phishing":
            print("\n[2] MITRE ATT&CK Mapping:")
            mitre_result = get_mitre_techniques("phishing")
            print(json.dumps(mitre_result, indent=2))

        elif category == "malware":
            print("\n[2] MITRE ATT&CK Mapping:")
            mitre_result = get_mitre_techniques("command and control")
            print(json.dumps(mitre_result, indent=2))

    else:
        print("Unknown IOC type.")

# ── STAGE 6: Related IOC Tool ──────────────────────────────────

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
def classify_known_scanner(ip_address: str) -> dict:
    """
    Classifies whether an IP belongs to known internet scanning infrastructure.
    This helps avoid over-labeling benign scanner traffic as malicious.
    """

    known_scanner_ranges = [
        {
            "company": "Palo Alto Networks Cortex Xpanse",
            "category": "attack_surface_scanner",
            "ranges": [
                "35.203.210.0/23",
                "144.86.173.0/24",
                "147.185.132.0/23",
                "162.216.149.0/24",
                "162.216.150.0/24",
                "172.105.147.0/24",
                "198.235.24.0/24",
                "205.210.31.0/24",
                "216.25.88.0/21",
            ],
            "classification": "known_scanner",
            "default_severity": "LOW",
            "notes": "Published Cortex Xpanse scanner range. Usually benign scanning, but still monitor if behavior is excessive.",
        },
        {
            "company": "Censys",
            "category": "internet_research_scanner",
            "ranges": [
                "162.142.125.0/24",
                "167.94.138.0/24",
                "167.94.145.0/24",
                "167.94.146.0/24",
                "167.248.133.0/24",
                "199.45.154.0/24",
                "199.45.155.0/24",
                "206.168.34.0/24",
                "206.168.35.0/24",
            ],
            "classification": "known_scanner",
            "default_severity": "LOW",
            "notes": "Censys scans public internet infrastructure for internet-wide measurement and attack surface visibility.",
        },
        {
            "company": "Shodan",
            "category": "internet_search_scanner",
            "ranges": [
                "207.90.244.0/24",
            ],
            "classification": "known_scanner",
            "default_severity": "LOW",
            "notes": "Shodan crawls internet-connected services. Treat as scanner traffic unless paired with exploit attempts or authentication failures.",
        },
    ]

    ip_obj = ipaddress.ip_address(ip_address)

    for scanner in known_scanner_ranges:
        for network in scanner["ranges"]:
            if ip_obj in ipaddress.ip_network(network):
                return {
                    "ip": ip_address,
                    "is_known_scanner": True,
                    "company": scanner["company"],
                    "category": scanner["category"],
                    "classification": scanner["classification"],
                    "default_severity": scanner["default_severity"],
                    "matched_range": network,
                    "notes": scanner["notes"],
                }

    return {
        "ip": ip_address,
        "is_known_scanner": False,
        "classification": "not_known_scanner",
        "default_severity": "UNKNOWN",
        "notes": "IP did not match known scanner ranges in the local scanner database.",
    }

# ── STAGE 8: IOC Timeline Tool ────────────────────────────────────────────────


    ip_obj = ipaddress.ip_address(ip_address)

    for scanner in known_scanner_ranges:
        for network in scanner["ranges"]:
            if ip_obj in ipaddress.ip_network(network):
                return {
                    "ip": ip_address,
                    "is_known_scanner": True,
                    "company": scanner["company"],
                    "category": scanner["category"],
                    "classification": scanner["classification"],
                    "default_severity": scanner["default_severity"],
                    "matched_range": network,
                    "notes": scanner["notes"],
                }

    return {
        "ip": ip_address,
        "is_known_scanner": False,
        "classification": "not_known_scanner",
        "default_severity": "UNKNOWN",
        "notes": "IP did not match known scanner ranges.",
    }


# Try all 3 sample cases without using the API
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

# ── Multiple Honeypot Events ────────────────────────────────────────────────
def enrich_honeypot_events(events: list) -> list:
    enriched_documents = []

    for event in events:
        source_ip = event.get("source_ip")

        if not source_ip:
            continue

        summary = build_intelligence_summary(source_ip)

        elastic_doc = convert_to_elastic_document(
            event,
            summary
        )

        enriched_documents.append(elastic_doc)

    return enriched_documents

# ── Deduplication + caching ────────────────────────────────────────────────
def enrich_honeypot_events_with_cache(events: list) -> list:
    """
    Enriches multiple STINGAR honeypot events while caching
    intelligence summaries per source IP.

    This prevents repeated API calls for the same IP.
    """

    enriched_documents = []
    intelligence_cache = {}

    for event in events:
        source_ip = event.get("source_ip")

        if not source_ip:
            continue

        if source_ip not in intelligence_cache:
            intelligence_cache[source_ip] = build_intelligence_summary(source_ip)
            cache_status = "miss"
        else:
            cache_status = "hit"

        summary = intelligence_cache[source_ip]

        elastic_doc = convert_to_elastic_document(
            event,
            summary
        )

        elastic_doc["elastic_metadata"]["cache_status"] = cache_status
        elastic_doc["elastic_metadata"]["cache_key"] = source_ip

        enriched_documents.append(elastic_doc)

    return enriched_documents

# ── Batch Summary ────────────────────────────────────────────────
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
                "threat_actor": actor,
                "severity": doc["threat"]["severity"],
                "recommended_action": get_cluster_recommended_action(
                    doc["threat"]["severity"]
                ),
                "recurrence": recurrence,
                "event_count": 0,
                "attack_types": set(),
                "destination_ports": set(),
            }

        cluster = clusters[cluster_key]

        cluster["event_count"] += 1

        cluster["attack_types"].add(
            doc["stingar"]["attack_type"]
        )

        cluster["destination_ports"].add(
            doc["destination"]["port"]
        )

    results = []

    for cluster in clusters.values():

        cluster["attack_types"] = sorted(
            list(cluster["attack_types"])
        )

        cluster["destination_ports"] = sorted(
            list(cluster["destination_ports"])
        )

        results.append(cluster)

    return results

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

#testing block
if __name__ == "__main__":

    # print("\nREAL CLAUDE AGENT TEST")

    # analysis, tool_calls = run_threat_intel_agent(
    #     "203.0.113.42",
    #     "ip_address"
    # )

    # print(f"\nClaude used {len(tool_calls)} tool(s):")
    # for call in tool_calls:
    #     print(f"- {call['tool']} {call['input']}")

    # print("\nClaude Analysis:")
    # print(analysis)

    # hash_data = lookup_file_hash(
    #     "d131dd02c5e6eec4693d9a0698aff95c",
    #     "md5"
    # )

    # graph = build_relationship_graph(hash_data)
    # display_relationship_graph(graph)

    # print(
    #     generate_threat_report(
    #         "d131dd02c5e6eec4693d9a0698aff95c",
    #         hash_data
    #     )
    # )

    # json_report = export_report_json(
    #     "d131dd02c5e6eec4693d9a0698aff95c",
    #     "file_hash",
    #     hash_data
    # )

    # print("\nSTRUCTURED JSON REPORT")
    # print(json.dumps(json_report, indent=2))

    # # with open("threat_report.json", "w") as file:
    # #     json.dump(json_report, file, indent=2)

    # print("\nJSON report generated successfully.")

    # print("\nRELATED IOC TEST")
    # print(json.dumps(
    #     find_related_iocs("203.0.113.42", "ip_address"),
    #     indent=2
    # ))

    # print("\nKNOWN SCANNER TEST")
    # print(json.dumps(
    #     classify_known_scanner("198.235.24.10"),
    #     indent=2
    # )   )

    # print(json.dumps(
    #     classify_known_scanner("203.0.113.42"),
    #     indent=2
    # )) 

    # print("\nGREYNOISE TEST")
    # print(
    #     json.dumps(
    #         classify_greynoise(
    #             "203.0.113.42"
    #         ),
    #         indent=2
    #     )
    # )

    # print("\nTIMELINE TEST")
    # print(
    #     json.dumps(
    #         lookup_ioc_timeline(
    #             "203.0.113.42",
    #             "ip_address"
    #         ),
    #         indent=2
    #     )
    # )

    # print("\nANONYMIZER TEST")
    # print(
    #     json.dumps(
    #         classify_anonymizer_network(
    #             "185.220.101.1"
    #         ),
    #         indent=2
    #     )
    # )

    # print("\nIP VERSION TEST")
    # print(json.dumps(
    #     analyze_ip_version("203.0.113.42"),
    #     indent=2
    # ))

    # print(json.dumps(
    #     analyze_ip_version("2606:4700:4700::1111"),
    #     indent=2
    # ))

    # print("\nENRICHED SEVERITY TEST")

    # ip = "203.0.113.42"

    # reputation_data = lookup_ip_reputation(ip)
    # scanner_data = classify_known_scanner(ip)
    # anonymizer_data = classify_anonymizer_network(ip)
    # greynoise_data = classify_greynoise(ip)
    # timeline_data = lookup_ioc_timeline(ip, "ip_address")

    # enriched_severity = calculate_enriched_severity(
    #     reputation_data=reputation_data,
    #     scanner_data=scanner_data,
    #     anonymizer_data=anonymizer_data,
    #     greynoise_data=greynoise_data,
    #     timeline_data=timeline_data,
    # )

    # print(json.dumps(enriched_severity, indent=2))

    # print("\nKNOWN SCANNER SEVERITY TEST")

    # scanner_ip = "198.235.24.10"

    # scanner_reputation_data = lookup_ip_reputation(scanner_ip)
    # scanner_scanner_data = classify_known_scanner(scanner_ip)
    # scanner_anonymizer_data = classify_anonymizer_network(scanner_ip)
    # scanner_greynoise_data = classify_greynoise(scanner_ip)
    # scanner_timeline_data = lookup_ioc_timeline(scanner_ip, "ip_address")

    # scanner_severity = calculate_enriched_severity(
    #     reputation_data=scanner_reputation_data,
    #     scanner_data=scanner_scanner_data,
    #     anonymizer_data=scanner_anonymizer_data,
    #     greynoise_data=scanner_greynoise_data,
    #     timeline_data=scanner_timeline_data,
    # )

    # print(json.dumps(scanner_severity, indent=2))

    # print("\nENRICHED SEVERITY TOOL TEST")
    # print(json.dumps(
    #     calculate_enriched_severity_tool("203.0.113.42"),
    #     indent=2
    # ))

    # print(json.dumps(
    #     calculate_enriched_severity_tool("198.235.24.10"),
    #     indent=2
    # ))  

    print("\nREAL ABUSEIPDB TEST")
    print(json.dumps(
        lookup_ip_reputation_abuseipdb("198.235.24.10"),
        indent=2
    ))

    print("\nINVESTIGATION OUTCOME TEST - KNOWN SCANNER")
    print(json.dumps(
        classify_investigation_outcome_tool("198.235.24.10"),
        indent=2
    ))

    print("\nINVESTIGATION OUTCOME TEST - MALICIOUS IP")
    print(json.dumps(
        classify_investigation_outcome_tool("203.0.113.42"),
        indent=2
    ))

    print("\nCAMPAIGN PROFILE TEST")

    print(json.dumps(
        build_campaign_profile(
            "203.0.113.42",
            "ip_address"
        ),
        indent=2
    ))

    print("\nTHREAT ACTOR TEST")

    campaign = build_campaign_profile(
        "203.0.113.42",
        "ip_address"
    )

    print(json.dumps(
        attribute_threat_actor(campaign),
        indent=2
    ))

    print("\nFULL INTELLIGENCE SUMMARY")

    print(json.dumps(
        build_intelligence_summary(
            "203.0.113.42"
        ),
        indent=2
    ))

    print("\nFULL INTELLIGENCE SUMMARY TOOL TEST")
    print(json.dumps(
        build_intelligence_summary("203.0.113.42"),
        indent=2
    ))

    #temp testing block 

    # print("\nREAL CLAUDE FULL SUMMARY TEST")

    # analysis, tool_calls = run_threat_intel_agent(
    #     "203.0.113.42",
    #     "ip_address"
    # )

    # print(f"\nClaude used {len(tool_calls)} tool(s):")
    # for call in tool_calls:
    #     print(f"- {call['tool']} {call['input']}")

    # print("\nClaude Analysis:")
    # print(analysis)

    print("\nELASTIC DOCUMENT TEST")

    sample_honeypot_event = {
        "source_ip": "203.0.113.42",
        "source_port": 55231,
        "destination_ip": "10.0.0.25",
        "destination_port": 22,
        "protocol": "ssh",
        "transport": "tcp",
        "sensor_id": "stingar-duke-sensor-01",
        "honeypot_type": "cowrie",
        "attack_type": "ssh_bruteforce",
    }

    summary = build_intelligence_summary(
        sample_honeypot_event["source_ip"]
    )

    elastic_doc = convert_to_elastic_document(
        sample_honeypot_event,
        summary
    )

    print(json.dumps(elastic_doc, indent=2))

    print("\nBATCH ELASTIC DOCUMENT TEST")

sample_events = [
    {
        "source_ip": "203.0.113.42",
        "source_port": 55231,
        "destination_ip": "10.0.0.25",
        "destination_port": 22,
        "protocol": "ssh",
        "transport": "tcp",
        "sensor_id": "stingar-duke-sensor-01",
        "honeypot_type": "cowrie",
        "attack_type": "ssh_bruteforce",
    },
    {
        "source_ip": "198.235.24.10",
        "source_port": 49530,
        "destination_ip": "10.0.0.25",
        "destination_port": 8080,
        "protocol": "http",
        "transport": "tcp",
        "sensor_id": "stingar-duke-sensor-01",
        "honeypot_type": "web_honeypot",
        "attack_type": "service_probe",
    },
]

batch_docs = enrich_honeypot_events(sample_events)

print(json.dumps(batch_docs, indent=2))

print("\nBATCH ELASTIC DOCUMENT CACHE TEST")

sample_events_with_duplicates = [
    {
        "source_ip": "203.0.113.42",
        "source_port": 55231,
        "destination_ip": "10.0.0.25",
        "destination_port": 22,
        "protocol": "ssh",
        "transport": "tcp",
        "sensor_id": "stingar-duke-sensor-01",
        "honeypot_type": "cowrie",
        "attack_type": "ssh_bruteforce",
    },
    {
        "source_ip": "203.0.113.42",
        "source_port": 55232,
        "destination_ip": "10.0.0.25",
        "destination_port": 23,
        "protocol": "telnet",
        "transport": "tcp",
        "sensor_id": "stingar-duke-sensor-01",
        "honeypot_type": "cowrie",
        "attack_type": "telnet_probe",
    },
    {
        "source_ip": "198.235.24.10",
        "source_port": 49530,
        "destination_ip": "10.0.0.25",
        "destination_port": 8080,
        "protocol": "http",
        "transport": "tcp",
        "sensor_id": "stingar-duke-sensor-01",
        "honeypot_type": "web_honeypot",
        "attack_type": "service_probe",
    },
]

cached_docs = enrich_honeypot_events_with_cache(
    sample_events_with_duplicates
)

print(json.dumps(cached_docs, indent=2))

print("\nBATCH SUMMARY TEST")

batch_summary = summarize_enriched_batch(cached_docs)

print(json.dumps(batch_summary, indent=2))

print("\nINCIDENT CLUSTER TEST")

clusters = build_incident_clusters(
    cached_docs
)

print(json.dumps(
    clusters,
    indent=2
))

print("\nPRIORITY QUEUE TEST")

prioritized = prioritize_incidents(
    clusters
)

print(json.dumps(
    prioritized,
    indent=2
))