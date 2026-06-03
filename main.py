import json
import anthropic
import os

# Hardcode the key directly for now
from dotenv import load_dotenv
import os

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
You are a senior cyber threat intelligence analyst.

Rules:
- Investigate efficiently.
- Do not call the same tool repeatedly for similar information.
- Maximum 5 tool calls.
- Do not invent hashes, domains, or IPs.
- Only investigate indicators explicitly returned by tools.
- Produce concise analyst reports.
"""

MAX_TURNS = 10  # prevents runaway loops and runaway costs


def process_tool_call(tool_name: str, tool_input: dict) -> str:
    """Routes Claude's tool requests to the right backend function."""
    handlers = {
        "lookup_ip_reputation": lambda inp: lookup_ip_reputation(inp["ip_address"]),
        "lookup_file_hash": lambda inp: lookup_file_hash(inp["file_hash"], inp["hash_type"]),
        "lookup_domain": lambda inp: lookup_domain(inp["domain"]),
        "get_mitre_techniques": lambda inp: get_mitre_techniques(inp["query"]),
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
        f"Query all relevant intelligence sources, cross-reference findings, "
        f"map to MITRE ATT&CK where applicable, and provide your assessment with "
        f"severity rating, confidence score, and recommended response actions."
    )

    messages = [{"role": "user", "content": user_message}]
    tool_calls_made = []

    for turn in range(MAX_TURNS):
        print(f"  [Turn {turn + 1}] Calling Claude...")

        response = client.messages.create( #fix api key to run this 
            model=MODEL_NAME,
            max_tokens=4096,
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


# Try all 3 sample cases without using the API
# run_mock_agent("203.0.113.42", "ip_address")
# run_mock_agent("d131dd02c5e6eec4693d9a0698aff95c", "file_hash")
# run_mock_agent("secure-bankofamerica-login.com", "domain")

#testing block
if __name__ == "__main__":

    print("\nREAL CLAUDE AGENT TEST")

    analysis, tool_calls = run_threat_intel_agent(
        "203.0.113.42",
        "ip_address"
    )

    print(f"\nClaude used {len(tool_calls)} tool(s):")
    for call in tool_calls:
        print(f"- {call['tool']} {call['input']}")

    print("\nClaude Analysis:")
    print(analysis)

    hash_data = lookup_file_hash(
        "d131dd02c5e6eec4693d9a0698aff95c",
        "md5"
    )

    graph = build_relationship_graph(hash_data)
    display_relationship_graph(graph)

    print(
        generate_threat_report(
            "d131dd02c5e6eec4693d9a0698aff95c",
            hash_data
        )
    )

    json_report = export_report_json(
        "d131dd02c5e6eec4693d9a0698aff95c",
        "file_hash",
        hash_data
    )

    print("\nSTRUCTURED JSON REPORT")
    print(json.dumps(json_report, indent=2))

    # with open("threat_report.json", "w") as file:
    #     json.dump(json_report, file, indent=2)

    print("\nSaved JSON report to threat_report.json")