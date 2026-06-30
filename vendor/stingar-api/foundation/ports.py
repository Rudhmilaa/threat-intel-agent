"""
Transport-protocol helpers for docker-compose port mapping.

Docker publishes a host port as TCP unless the mapping carries an explicit
"/udp" suffix. A honeypot whose listener is UDP (SNMP, TFTP, BACnet, IPMI,
SIP, NTP, etc.) therefore receives no traffic at all when its mapping is
emitted as a bare "host:container", regardless of the cloud firewall. The
foundation builders construct those mappings, so they must know which services
are UDP and append the suffix.

This module centralises that knowledge so every foundation (the per-honeypot
builders and the GenericFoundation that backs HP App Store deployments) agrees
on it. Detection order:

  1. An explicit transport wins -- a mapping string already carrying "/udp" or
     "/tcp", or a caller-supplied transport ("udp" / "tcp" / "both").
  2. Otherwise the service is classified by well-known protocol name and/or
     well-known container port number.

TCP is Docker's default, so "/tcp" is normalised to no suffix (keeps mappings
for the common case unchanged). "both" emits a TCP mapping and a "/udp" mapping
for services that genuinely listen on both transports (e.g. DNS).
"""

# Well-known UDP service names (lowercase). Dual-transport services whose
# honeypot deployments are overwhelmingly UDP (dns, sip) are included; an
# explicit transport on the mapping/config overrides this for the rare TCP case.
UDP_PROTOCOLS = frozenset({
    "snmp", "snmptrap", "tftp", "bacnet", "ipmi", "ntp", "sip", "syslog",
    "ike", "isakmp", "l2tp", "netbios", "netbios-ns", "nbns", "mdns",
    "ssdp", "upnp", "wsdd", "coap", "dhcp", "dns", "radius", "openvpn",
})

# Well-known UDP container ports (IANA assignments for the services above).
UDP_PORTS = frozenset({
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 623, 1194,
    1701, 1812, 1813, 1900, 3702, 4500, 5060, 5353, 5683, 47808,
})


def is_udp(protocol=None, port=None):
    """Return True when a service is a well-known UDP service.

    :param protocol: service name (e.g. "snmp"); matched case-insensitively
    :param port: container/service port number (int or numeric str)
    """
    if protocol and str(protocol).lower() in UDP_PROTOCOLS:
        return True
    if port is not None:
        try:
            if int(port) in UDP_PORTS:
                return True
        except (TypeError, ValueError):
            pass
    return False


def _normalize_transport(transport):
    """Map a free-form transport hint to 'udp', 'tcp', 'both', or None."""
    if not transport:
        return None
    t = str(transport).strip().lower()
    if t in ("udp",):
        return "udp"
    if t in ("tcp",):
        return "tcp"
    if t in ("both", "tcp+udp", "udp+tcp", "tcp/udp", "udp/tcp"):
        return "both"
    return None


def apply_transport(mapping, protocol=None, port=None, transport=None):
    """Return docker-compose port mapping(s) with the correct transport suffix.

    Always returns a list (one entry for tcp/udp, two for "both") so callers can
    ``extend`` their port list uniformly.

    :param mapping: bare "host:container" mapping (no transport suffix)
    :param protocol: service name used for UDP classification
    :param port: container port used for UDP classification (defaults to the
                 container side parsed from ``mapping``)
    :param transport: explicit transport hint ("udp"/"tcp"/"both"); overrides
                      name/port classification
    """
    # An already-suffixed mapping is authoritative; pass it through untouched.
    if mapping.endswith("/udp") or mapping.endswith("/tcp"):
        return [mapping]

    decided = _normalize_transport(transport)
    if decided is None:
        # Classify by service name OR by ANY well-known port in the mapping.
        # Both the host and container sides are checked: a mapping may expose a
        # well-known UDP port on the host while using an arbitrary container
        # port (e.g. "161:16100"), or vice versa.
        candidate_ports = [port] if port is not None else []
        for token in mapping.split("/", 1)[0].split(":"):
            candidate_ports.append(token)
        decided = (
            "udp" if (is_udp(protocol)
                      or any(is_udp(port=c) for c in candidate_ports))
            else "tcp"
        )

    if decided == "both":
        return [mapping, mapping + "/udp"]
    if decided == "udp":
        return [mapping + "/udp"]
    # tcp is docker's default; no suffix keeps the mapping unchanged.
    return [mapping]
