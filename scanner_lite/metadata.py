"""Investigation metadata: behavior tags, frequency tier, priority."""

from __future__ import annotations

from typing import Any, Optional

FREQUENCY_TIERS = ("normal", "high", "excessive")
PRIORITIES = ("informational", "low", "medium", "high", "critical")

HIGH_EVENTS_PER_IP = 10
EXCESSIVE_EVENTS_PER_IP = 30


def extract_honeypot_context(event: dict | None) -> dict:
    """Pull hpData / STINGAR fields from normalized or raw event."""
    if not event:
        return {}

    raw = event.get("original") or event
    hp = raw.get("hpData") or {}
    headers = hp.get("headers") or {}

    return {
        "event_type": hp.get("eventType") or event.get("attack_type"),
        "method": hp.get("method"),
        "path": hp.get("path") or hp.get("fullPath"),
        "user_agent": headers.get("UserAgent") or headers.get("User-Agent"),
        "honeypot_app": raw.get("app") or event.get("honeypot_type"),
        "protocol": hp.get("protocol") or event.get("protocol"),
    }


def derive_behavior_tags(ctx: dict) -> list[str]:
    tags: list[str] = []
    ua = (ctx.get("user_agent") or "").lower()
    path = (ctx.get("path") or "").lower()
    event_type = (ctx.get("event_type") or "").lower()

    if event_type == "peoplesoft-scan" or "/ps/signon.html" in path:
        tags.append("peoplesoft_probe")
    if ctx.get("method") == "HEAD":
        tags.append("head_fingerprint")
    if ua == "go-http-client/1.1":
        tags.append("go_http_client")
    if ctx.get("honeypot_app") == "peoplesoft":
        tags.append("application_layer_recon")

    return tags


def derive_scanner_attribution(
    scanner_tag: dict | None,
    behavior_tags: list[str],
) -> str:
    if scanner_tag and scanner_tag.get("vendor"):
        return f"known:{scanner_tag['vendor']}"
    if "go_http_client" in behavior_tags:
        return "unidentified_go_scanner"
    if behavior_tags:
        return "unidentified_scanner"
    return "none"


def frequency_tier(events_for_ip: int) -> str:
    if events_for_ip >= EXCESSIVE_EVENTS_PER_IP:
        return "excessive"
    if events_for_ip >= HIGH_EVENTS_PER_IP:
        return "high"
    return "normal"


def derive_investigation_classification(
    outcome_category: str,
    scanner_tag: dict | None,
    behavior_tags: list[str],
    frequency: str,
) -> str:
    if scanner_tag and outcome_category == "benign":
        if frequency in ("high", "excessive"):
            return "known_scanner_high_noise"
        return "known_scanner"

    if "peoplesoft_probe" in behavior_tags:
        return "active_application_recon"

    if behavior_tags and frequency in ("high", "excessive"):
        return "unidentified_aggressive_scanner"

    if outcome_category == "malicious":
        return "confirmed_malicious_infrastructure"

    if outcome_category == "suspicious":
        return "active_reconnaissance_or_abuse"

    return "unknown"


def derive_priority(
    outcome_category: str,
    frequency: str,
    behavior_tags: list[str],
) -> str:
    if outcome_category == "malicious":
        return "critical"

    if outcome_category == "benign":
        return "low" if frequency == "normal" else "medium"

    if frequency == "excessive" or "peoplesoft_probe" in behavior_tags:
        return "high"

    if frequency == "high" or outcome_category == "suspicious":
        return "medium"

    return "low"


def build_investigation_metadata(
    *,
    outcome: dict,
    scanner_tag: dict | None,
    event: dict | None,
    events_in_batch: int = 1,
    events_today: Optional[int] = None,
    events_for_ip: Optional[int] = None,
) -> dict:
    """Build investigation metadata.

    ``events_today`` drives frequency/priority (cross-request history + current batch).
    ``events_in_batch`` is the count of this IP in the current HTTP payload only.
    ``events_for_ip`` is deprecated; treated as ``events_today`` when provided alone.
    """
    if events_for_ip is not None and events_today is None:
        events_today = events_for_ip
    today_count = events_today if events_today is not None else events_in_batch

    ctx = extract_honeypot_context(event)
    behavior_tags = derive_behavior_tags(ctx)
    freq = frequency_tier(today_count)
    outcome_category = outcome.get("outcome_category", "unknown")

    return {
        "investigation_classification": derive_investigation_classification(
            outcome_category,
            scanner_tag,
            behavior_tags,
            freq,
        ),
        "scanner_attribution": derive_scanner_attribution(scanner_tag, behavior_tags),
        "behavior_tags": behavior_tags,
        "frequency_tier": freq,
        "priority": derive_priority(outcome_category, freq, behavior_tags),
        "events_in_batch": events_in_batch,
        "events_today": today_count,
    }


def honeypot_signals_from_event(event: dict | None) -> dict[str, Any]:
    """Signals fragment for classifier re-run from honeypot event context."""
    ctx = extract_honeypot_context(event)
    behavior_tags = derive_behavior_tags(ctx)
    if not behavior_tags:
        return {}
    return {"honeypot": {"behavior_tags": behavior_tags, **ctx}}
