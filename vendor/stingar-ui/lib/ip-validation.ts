/**
 * Validate IP address or CIDR format for Attack Analysis search filter.
 * Supports IPv4, IPv6, and CIDR notation.
 */
export function isValidIpOrCidr(value: string): boolean {
  if (!value || typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!trimmed) return false;

  try {
    // Try single IP (IPv4 or IPv6)
    if (isValidIp(trimmed)) return true;
    // Try CIDR
    if (isValidCidr(trimmed)) return true;
    return false;
  } catch {
    return false;
  }
}

function isValidIp(value: string): boolean {
  // IPv4: dotted decimal
  const ipv4Regex =
    /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Regex.test(value)) return true;

  // IPv6: simplified check (hex groups separated by :)
  const ipv6Regex =
    /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4})?::(?:(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4})?$/;
  if (ipv6Regex.test(value)) return true;

  return false;
}

function isValidCidr(value: string): boolean {
  if (!value.includes("/")) return false;
  const [network, prefix] = value.split("/");
  if (!network || !prefix) return false;

  const prefixNum = parseInt(prefix, 10);
  if (isNaN(prefixNum) || prefixNum < 0) return false;

  if (isValidIp(network)) {
    // IPv4 CIDR: allow /8, /16, /17-/32. Reject /0-/7 and /9-/15 (causes backend 500)
    if (network.includes(".") && prefixNum <= 32) {
      if (prefixNum === 8 || prefixNum >= 16) return true;
    }
    // IPv6 CIDR: prefix 0-128 (no backend restriction for IPv6 yet)
    if (network.includes(":") && prefixNum <= 128) return true;
  }
  return false;
}

export function getIpFilterError(value: string): string | null {
  if (!value || typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (isValidIpOrCidr(trimmed)) return null;
  // Check for unsupported CIDR prefix (IPv4 only): /0-/7 and /9-/15
  if (trimmed.includes("/") && trimmed.includes(".")) {
    const prefixNum = parseInt(trimmed.split("/")[1], 10);
    if (!isNaN(prefixNum) && (prefixNum <= 7 || (prefixNum >= 9 && prefixNum <= 15))) {
      return "Use /8, /16, or /24 (e.g. 10.0.0.0/8, 147.224.0.0/16)";
    }
  }
  return "Enter a valid IP address or CIDR (e.g. 192.168.1.1 or 10.0.0.0/24)";
}
