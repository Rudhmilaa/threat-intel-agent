"""
Suricata rule generator for STINGAR honeypot signatures.

Generates valid Suricata rules from HASSH (SSH), JA3 (TLS), and SSH software
fingerprints extracted from Cowrie and Dionaea honeypot sessions.

Uses a handler-per-type pattern with SID namespace partitioning.
"""

import datetime
from util.rule_registry import RULE_TYPES


def _escape_content(val):
    """Escape backslash and double-quote for Suricata content modifier."""
    if not val:
        return ""
    return str(val).replace("\\", "\\\\").replace('"', '\\"')


def _rule_hassh(sig, sid, created_at):
    """Generate HASSH rule."""
    hash_val = sig.get('hash', '')
    hash_short = hash_val[:8] if len(hash_val) >= 8 else hash_val
    source = sig.get('source', 'stingar')
    return (
        f'alert ssh any any -> any any (msg:"STINGAR Honeypot HASSH {hash_short}"; '
        f'ssh.hassh; content:"{_escape_content(hash_val)}"; sid:{sid}; rev:1; '
        f'classtype:trojan-activity; metadata:source stingar-{source},created_at {created_at};)'
    )


def _rule_ja3(sig, sid, created_at):
    """Generate JA3 rule."""
    hash_val = sig.get('hash', '')
    hash_short = hash_val[:8] if len(hash_val) >= 8 else hash_val
    source = sig.get('source', 'stingar')
    return (
        f'alert tls any any -> any any (msg:"STINGAR Honeypot JA3 {hash_short}"; '
        f'ja3.hash; content:"{_escape_content(hash_val)}"; sid:{sid}; rev:1; '
        f'classtype:trojan-activity; metadata:source stingar-{source},created_at {created_at};)'
    )


def _rule_ja3s(sig, sid, created_at):
    """Generate JA3S rule."""
    hash_val = sig.get('hash', '')
    hash_short = hash_val[:8] if len(hash_val) >= 8 else hash_val
    source = sig.get('source', 'stingar')
    return (
        f'alert tls any any -> any any (msg:"STINGAR Honeypot JA3S {hash_short}"; '
        f'ja3s.hash; content:"{_escape_content(hash_val)}"; sid:{sid}; rev:1; '
        f'classtype:trojan-activity; metadata:source stingar-{source},created_at {created_at};)'
    )


def _rule_ssh_software(sig, sid, created_at):
    """Generate ssh.software rule for SSH client version string."""
    val = sig.get('hash', '')  # 'hash' holds the version string for ssh_software
    val_short = val[:20] + "..." if len(val) > 20 else val
    source = sig.get('source', 'stingar')
    return (
        f'alert ssh any any -> any any (msg:"STINGAR Honeypot SSH {val_short}"; '
        f'ssh.software; content:"{_escape_content(val)}"; nocase; sid:{sid}; rev:1; '
        f'classtype:trojan-activity; metadata:source stingar-{source},created_at {created_at};)'
    )


RULE_HANDLERS = {
    'hassh': _rule_hassh,
    'ja3': _rule_ja3,
    'ja3s': _rule_ja3s,
    'ssh_software': _rule_ssh_software,
}


def generate_rules(signatures):
    """
    Generate Suricata rules from signature list.

    :param signatures: List of dicts with keys: type, hash, source
    :return: Suricata rule text as string
    """
    lines = []
    lines.append("# STINGAR Honeypot Rules - Generated " + datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S") + " UTC")
    lines.append("# Source: Cowrie HASSH/SSH, Dionaea JA3/JA3S")
    lines.append("")

    created_at = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    sid_counters = {t: cfg['sid_base'] for t, cfg in RULE_TYPES.items()}

    for sig in signatures:
        sig_type = sig.get('type', '')
        hash_val = sig.get('hash', '')
        if not hash_val or not isinstance(hash_val, str):
            continue

        handler = RULE_HANDLERS.get(sig_type)
        if not handler:
            continue

        cfg = RULE_TYPES.get(sig_type, {})
        sid_base = cfg.get('sid_base', 9000000)
        sid_range = cfg.get('sid_range', 1000)
        sid = sid_counters.get(sig_type, sid_base)
        if sid >= sid_base + sid_range:
            continue  # SID range exhausted, skip
        sid_counters[sig_type] = sid + 1

        rule = handler(sig, sid, created_at)
        lines.append(rule)

    return "\n".join(lines) + "\n"
