"""Apply safelist, sharing, and response policy to enrichment outputs."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Optional

from threat_intel.safelist import SafelistRegistry
from threat_intel.sharing_policy import (
    _delete_nested_value,
    _get_nested_value,
    destination_in_blocked_cidr,
    load_sharing_policy,
)


def apply_policy_to_summary(
    summary: dict,
    ip_address: str,
    client_id: Optional[str] = None,
    direction: str = "inbound",
) -> dict:
    if not client_id:
        return summary

    result = deepcopy(summary)
    safelist = SafelistRegistry.for_client(client_id)
    match = safelist.match_ip(ip_address, direction=direction)
    if not match:
        return result

    actions = match["actions"]
    severity = result.get("severity", {})
    investigation = result.get("investigation", {})

    if actions.get("cap_severity"):
        capped = SafelistRegistry.cap_severity(
            severity.get("severity", "INFORMATIONAL"),
            actions["cap_severity"],
        )
        severity["severity"] = capped
        result["severity"] = severity

    policy_tags = result.setdefault("policy_tags", [])
    policy_tags.append("policy:safelisted")
    if actions.get("never_block"):
        policy_tags.append("policy:never_block")
    if actions.get("never_escalate"):
        policy_tags.append("policy:never_escalate")

    investigation["safelist"] = {
        "matched": True,
        "provider": match["provider"],
        "matched_range": match["matched_range"],
        "actions": actions,
    }
    result["investigation"] = investigation
    return result


def annotate_document_policy(document: dict, client_id: str) -> dict:
    doc = deepcopy(document)
    source_ip = doc.get("source", {}).get("ip")
    if not source_ip:
        return doc

    safelist = SafelistRegistry.for_client(client_id)
    match = safelist.match_ip(source_ip, direction="inbound")
    if match:
        doc.setdefault("policy", {})
        doc["policy"]["safelist"] = match
        doc.setdefault("taxonomy", {})
        doc["taxonomy"].setdefault("tags", [])
        doc["taxonomy"]["tags"].extend(["policy:safelisted", "policy:never_block"])

    return doc


def can_use_llm(client_id: str) -> bool:
    policy = load_sharing_policy(client_id)
    return bool(policy.get("global_joined"))


def sanitize_document(document: dict, policy: dict) -> dict:
    doc = deepcopy(document)

    for field_path in policy.get("never_share_fields", []):
        _delete_nested_value(doc, field_path)

    classification = _get_nested_value(doc, "investigation.classification")
    if classification in policy.get("never_share_classifications", []):
        doc.setdefault("taxonomy", {})
        tags = doc["taxonomy"].setdefault("tags", [])
        if "policy:share_blocked" not in tags:
            tags.append("policy:share_blocked")

    destination_ip = _get_nested_value(doc, "destination.ip")
    if destination_in_blocked_cidr(
        destination_ip,
        policy.get("never_share_destination_cidrs", []),
    ):
        doc.setdefault("taxonomy", {})
        tags = doc["taxonomy"].setdefault("tags", [])
        if "policy:share_blocked" not in tags:
            tags.append("policy:share_blocked")

    taxonomy_tags = _get_nested_value(doc, "taxonomy.tags") or []
    blocked_tag_set = set(policy.get("never_share_if_tags", []))
    if blocked_tag_set.intersection(taxonomy_tags):
        doc.setdefault("taxonomy", {})
        if "policy:share_blocked" not in doc["taxonomy"].setdefault("tags", []):
            doc["taxonomy"]["tags"].append("policy:share_blocked")

    return doc


def evaluate_shareability(document: dict, client_id: str) -> dict:
    policy = load_sharing_policy(client_id)

    if policy.get("deployment_mode") == "local_only":
        return {
            "allowed": False,
            "reason": "deployment_mode is local_only",
            "sanitized_document": None,
        }

    if not policy.get("share_enriched_documents", True):
        return {
            "allowed": False,
            "reason": "share_enriched_documents disabled",
            "sanitized_document": None,
        }

    classification = _get_nested_value(document, "investigation.classification")
    if classification in policy.get("never_share_classifications", []):
        return {
            "allowed": False,
            "reason": f"classification {classification} is blocked from sharing",
            "sanitized_document": sanitize_document(document, policy),
        }

    destination_ip = _get_nested_value(document, "destination.ip")
    if destination_in_blocked_cidr(
        destination_ip,
        policy.get("never_share_destination_cidrs", []),
    ):
        return {
            "allowed": False,
            "reason": "destination IP is in a never-share CIDR range",
            "sanitized_document": sanitize_document(document, policy),
        }

    taxonomy_tags = _get_nested_value(document, "taxonomy.tags") or []
    blocked_tag_set = set(policy.get("never_share_if_tags", []))
    if blocked_tag_set.intersection(taxonomy_tags):
        return {
            "allowed": False,
            "reason": "document matched a never-share tag rule",
            "sanitized_document": sanitize_document(document, policy),
        }

    sanitized = sanitize_document(document, policy)
    taxonomy_tags = _get_nested_value(sanitized, "taxonomy.tags") or []
    if "policy:share_blocked" in taxonomy_tags:
        return {
            "allowed": False,
            "reason": "document matched a sharing block rule",
            "sanitized_document": sanitized,
        }

    return {
        "allowed": True,
        "reason": "allowed by sharing policy",
        "sanitized_document": sanitized,
    }


def build_client_policy_summary(client_id: str) -> dict:
    policy = load_sharing_policy(client_id)
    safelist = SafelistRegistry.for_client(client_id)
    return {
        "client_id": client_id,
        "deployment_mode": policy.get("deployment_mode"),
        "global_joined": policy.get("global_joined"),
        "sharing_policy": policy,
        "safelist_entry_count": len(safelist.list_entries()),
        "safelist_range_count": len(safelist.table()),
        "llm_enabled": can_use_llm(client_id),
    }
