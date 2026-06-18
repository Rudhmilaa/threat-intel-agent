import ipaddress
import json
import anthropic
import os
import requests

from dotenv import load_dotenv
from datetime import datetime, timezone

from threat_intel.scanners import (
    ScannerRegistry,
    classify_known_scanner,
    configure_scanners,
    list_scanner_inventory,
)
from threat_intel.scanner_inventory_maintenance import refresh_scanner_inventory

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


from threat_intel.campaign import attribute_threat_actor, build_campaign_profile
from threat_intel.documents import convert_to_elastic_document
from threat_intel.incidents import (
    build_incident_clusters,
    detect_recurring_attacker,
    prioritize_incidents,
    summarize_enriched_batch,
)
from threat_intel.investigation import (
    classify_investigation_outcome,
    classify_investigation_outcome_tool,
)
from threat_intel.intelligence_summary import (
    build_intelligence_summary,
    enrich_honeypot_events,
    enrich_honeypot_events_with_cache,
)
from threat_intel.lookups import (
    analyze_ip_version,
    calculate_risk_score,
    classify_anonymizer_network,
    classify_greynoise,
    find_related_iocs,
    get_mitre_techniques,
    lookup_domain,
    lookup_file_hash,
    lookup_ioc_timeline,
    lookup_ip_reputation,
    lookup_ip_reputation_abuseipdb,
)
from threat_intel.severity import (
    calculate_enriched_severity,
    calculate_enriched_severity_tool,
)

load_dotenv()

_client = None
MODEL_NAME = "claude-sonnet-4-6"


def get_anthropic_client():
    global _client
    if _client is None:
        _client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
    return _client


def ensure_agent_ready() -> None:
    configure_scanners(ScannerRegistry.for_client())

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
        "description": "Determine whether an IP address belongs to a known internet scanner or security research organization. Uses known_scanner_inventory.csv with vendor CIDRs, source URLs, last_verified dates, and confidence levels. Only high/medium-confidence documented ranges are used for automatic classification.",
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
        "name": "list_scanner_inventory",
        "description": "Return the known scanner inventory spreadsheet (vendor, scanner_type, cidr, source_url, last_verified, confidence) plus coverage stats. Use this to review which scanners have documented CIDRs versus pending or dynamic sources.",
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },

    {
        "name": "refresh_scanner_inventory",
        "description": "Refresh known_scanner_inventory.csv from official vendor feeds (Censys, Cortex Xpanse, ONYPHE, LeakIX, BinaryEdge), verify pending vendor documentation URLs, update last_verified stamps, and reload the active scanner registry.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dry_run": {
                    "type": "boolean",
                    "description": "If true, fetch feeds and return a change report without writing the CSV.",
                }
            },
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


def attach_taxonomy_to_clusters(clusters: list) -> list:
    from threat_intel.taxonomy import attach_taxonomy_to_clusters as _attach

    return _attach(clusters)

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
- Scanner attribution comes from known_scanner_inventory.csv. Use list_scanner_inventory when asked about scanner coverage or maintenance.
- Use refresh_scanner_inventory to sync official vendor feeds before reporting on scanner inventory freshness.
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
        "list_scanner_inventory": lambda inp: list_scanner_inventory(),
        "refresh_scanner_inventory": lambda inp: refresh_scanner_inventory(
            write_changes=not inp.get("dry_run", False),
            reload_registry=not inp.get("dry_run", False),
        ).to_dict(),
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
    ensure_agent_ready()
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

        response = get_anthropic_client().messages.create(
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