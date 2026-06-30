"""
Rule type registry for IDS rules extraction and generation.

Maps rule types to Suricata keywords, SID ranges, and ES extraction.
New rule types can be added by extending RULE_TYPES and APP_EXTRACTORS.
"""

# SID namespace partitioning (per recommendation)
# 9000000-9000999: HASSH
# 9001000-9001999: JA3
# 9002000-9002999: JA3S
# 9003000-9003999: SSH software
RULE_TYPES = {
    'hassh': {'sid_base': 9000000, 'sid_range': 1000, 'keyword': 'ssh.hassh'},
    'ja3': {'sid_base': 9001000, 'sid_range': 1000, 'keyword': 'ja3.hash'},
    'ja3s': {'sid_base': 9002000, 'sid_range': 1000, 'keyword': 'ja3s.hash'},
    'ssh_software': {'sid_base': 9003000, 'sid_range': 1000, 'keyword': 'ssh.software'},
}

# App -> list of (rule_type, extractor_fn)
# extractor_fn(hp_data) -> str or None
APP_EXTRACTORS = {
    'cowrie': [
        ('hassh', lambda hp: (hp.get('kex') or {}).get('hassh')),
        ('ssh_software', lambda hp: hp.get('version') or (hp.get('kex') or {}).get('clientVersion')),
    ],
    'dionaea': [
        ('ja3', lambda hp: hp.get('ja3')),
        ('ja3s', lambda hp: hp.get('ja3s')),
    ],
}


def get_extractors_for_app(app, rule_types):
    """Return list of (rule_type, extractor) for the given app and requested rule types."""
    extractors = APP_EXTRACTORS.get(app, [])
    return [(t, fn) for t, fn in extractors if t in rule_types]


def get_apps_for_rule_types(rule_types):
    """Return list of (app, extractors) that provide any of the requested rule types."""
    result = []
    for app, extractors in APP_EXTRACTORS.items():
        filtered = get_extractors_for_app(app, rule_types)
        if filtered:
            result.append((app, filtered))
    return result
