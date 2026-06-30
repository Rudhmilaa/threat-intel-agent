"""
IDS Rules Feed: on-demand generation with disk cache.

Rules are generated when the feed endpoint is requested and the cache is stale or missing.
A 5-minute TTL cache coalesces multiple IDS pollers. No background scheduler.
"""

import logging
import os
import threading
from datetime import datetime, timedelta

from resources.store_config import read_stingar_env

logger = logging.getLogger(__name__)

# Shared state (updated by generate_rules_and_cache, read by feed/status)
_feed_state = {
    'last_generated': None,
    'total_hassh': 0,
    'total_ja3': 0,
    'total_ja3s': 0,
    'total_ssh_software': 0,
    'date_range': {'from': None, 'to': None},
}
_state_lock = threading.Lock()


def _parse_feed_date_range(date_range_str):
    """Convert IDS_RULES_FEED_DATE_RANGE (30d, 7d, 24h, etc.) to from_date, to_date."""
    to_date = datetime.utcnow()
    val = (date_range_str or '30d').strip().lower()
    try:
        if val.endswith('d'):
            days = int(val[:-1])
            from_date = to_date - timedelta(days=days)
        elif val.endswith('h'):
            hours = int(val[:-1])
            from_date = to_date - timedelta(hours=hours)
        else:
            from_date = to_date - timedelta(days=30)
    except (ValueError, TypeError):
        from_date = to_date - timedelta(days=30)
    return from_date.isoformat(), to_date.isoformat()


def is_cache_fresh(cache_path, ttl_seconds):
    """Return True if cache file exists and was written within ttl_seconds."""
    if not cache_path or ttl_seconds <= 0:
        return False
    try:
        mtime = os.path.getmtime(cache_path)
        age = datetime.utcnow().timestamp() - mtime
        return age < ttl_seconds
    except OSError:
        return False


def generate_rules_and_cache(format, date_range_str=None):
    """
    Generate rules for the given format, write to disk cache, update shared state.
    Returns (rules_text, summary). Raises on ES or generation failure.
    """
    from resources import es
    from util.suricata_rules import generate_rules
    from util.snort_rules import generate_snort_rules

    env = read_stingar_env()
    date_range_str = date_range_str or env.get('IDS_RULES_FEED_DATE_RANGE', '30d')
    from_date, to_date = _parse_feed_date_range(date_range_str)

    results = es.get_signatures(
        from_date=from_date,
        to_date=to_date,
        app_filter='all',
        rule_types=['hassh', 'ja3', 'ja3s', 'ssh_software'],
        limit=500
    )
    signatures = results.get('signatures', [])
    summary = results.get('summary', {})

    suricata_path = get_cache_path('suricata')
    snort_path = get_cache_path('snort')
    cache_dir = os.path.dirname(suricata_path) or '.'
    os.makedirs(cache_dir, exist_ok=True)

    suricata_text = generate_rules(signatures)
    snort_text = generate_snort_rules(signatures)

    for path, text in [(suricata_path, suricata_text), (snort_path, snort_text)]:
        tmp_path = path + '.tmp'
        with open(tmp_path, 'w', encoding='utf-8') as f:
            f.write(text)
        os.replace(tmp_path, path)

    with _state_lock:
        _feed_state['last_generated'] = datetime.utcnow().isoformat() + 'Z'
        _feed_state['total_hassh'] = summary.get('total_hassh', 0)
        _feed_state['total_ja3'] = summary.get('total_ja3', 0)
        _feed_state['total_ja3s'] = summary.get('total_ja3s', 0)
        _feed_state['total_ssh_software'] = summary.get('total_ssh_software', 0)
        _feed_state['date_range'] = {'from': from_date, 'to': to_date}

    rules_text = snort_text if format == 'snort' else suricata_text
    logger.info(f"IDS rules feed generated: {len(signatures)} signatures, {format} cache written")
    return rules_text, summary


def get_feed_state():
    """Return current feed state (last_generated, counts, date_range)."""
    with _state_lock:
        return dict(_feed_state)


def get_cache_path(format='suricata'):
    """Return configured cache file path for the given format (suricata or snort)."""
    env = read_stingar_env()
    base = env.get('IDS_RULES_CACHE_PATH', '/var/lib/stingar/ids-rules/stingar-honeypot.rules')
    if format == 'snort':
        if base.endswith('.rules'):
            return base[:-6] + '-snort.rules'
        return base + '-snort'
    return base
