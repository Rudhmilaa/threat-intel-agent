/**
 * Unified Severity Calculation System
 * 
 * This module provides severity calculation for all honeypot types while maintaining
 * backward compatibility with existing honeypots (Cowrie, Dionaea, Conpot, Amun, etc.)
 * 
 * Key Design Principles:
 * - Preserve existing Cowrie logic exactly as-is
 * - Add new logic only for honeygo (synsor), trainpot (ai-scraper), and future honeypots we control
 * - Default to LOW severity for existing honeypots that cannot be updated
 */

export enum SeverityLevel {
  LOW = 0,
  MEDIUM = 1,
  HIGH = 2,
  CRITICAL = 3,
  EXTREME = 4
}

export interface SeverityIndicator {
  level: SeverityLevel;
  score: number;
  color: string;
  label: string;
  description: string;
}

/**
 * Main severity calculator - routes to appropriate handler based on honeypot type
 */
export function calculateSeverity(hpData: any, session: { app: string }): SeverityIndicator {
  const app = session.app?.toLowerCase() || '';

  // Route to appropriate calculator based on honeypot type
  switch (app) {
    case 'cowrie':
      // PRESERVE EXISTING COWRIE LOGIC - DO NOT MODIFY
      return calculateCowrieSeverity(hpData);

    case 'synsor': // honeygo uses "synsor" as app name
      return calculateHoneygoSeverity(hpData);

    case 'trainpot':
    case 'ai-scraper':
    case 'scraper-hp':
    case 'scraper':
      return calculateTrainpotSeverity(hpData);

    default:
      // EXISTING HONEYPOTS (dionaea, conpot, amun, etc.) - maintain current behavior
      return getDefaultSeverity(hpData);
  }
}

/**
 * EXISTING COWRIE LOGIC - PRESERVED EXACTLY AS-IS
 * This function replicates the current getSeverityValue logic from sessions-table.tsx
 * DO NOT MODIFY without careful consideration of backward compatibility
 */
function calculateCowrieSeverity(hpData: any): SeverityIndicator {
  if (hpData === undefined || !hpData || Object.keys(hpData).length === 0) {
    return getDefaultSeverity(hpData);
  }

  let severityScore = 0;
  let level = SeverityLevel.LOW;

  // Add to severity score based on credentials
  if (hpData.credentials?.length > 0) {
    severityScore += 1; // Medium severity
    level = SeverityLevel.MEDIUM;
    if (hpData.credentials[0]?.success === true) {
      severityScore += 1; // High severity
      level = SeverityLevel.HIGH;
    }
  }

  // Add to severity score for commands
  if (hpData?.commands && hpData.commands.length > 0) {
    severityScore += 2;
    level = SeverityLevel.HIGH;
  }

  // Add to severity score for wget/tftp commands
  const hasDownloadCommand = hpData?.commands?.some((cmd: string) => {
    const lowerCmd = cmd.toLowerCase();
    return lowerCmd.includes("wget") || lowerCmd.includes("tftp");
  });
  if (hasDownloadCommand) {
    severityScore += 3;
    level = SeverityLevel.CRITICAL;
  }

  // Normalize score to 0-1 range (original was 0-6)
  const normalizedScore = Math.min(severityScore / 6, 1.0);

  return {
    level,
    score: normalizedScore,
    color: getSeverityColor(level),
    label: getSeverityLabel(level),
    description: generateCowrieDescription(hpData, level)
  };
}

function generateCowrieDescription(hpData: any, level: SeverityLevel): string {
  const parts: string[] = [];

  if (hpData.credentials?.length > 0) {
    const success = hpData.credentials[0]?.success;
    parts.push(success ? "Successful login" : "Login attempt");
  }

  if (hpData?.commands && hpData.commands.length > 0) {
    parts.push(`${hpData.commands.length} command(s)`);
  }

  const hasDownloadCommand = hpData?.commands?.some((cmd: string) => {
    const lowerCmd = cmd.toLowerCase();
    return lowerCmd.includes("wget") || lowerCmd.includes("tftp");
  });
  if (hasDownloadCommand) {
    parts.push("Download command detected");
  }

  return parts.join(" • ") || "Cowrie session";
}

/**
 * TRAINPOT SEVERITY CALCULATOR
 * AI scraper / AI training crawler detection honeypot
 * Logic: violation=true -> HIGH; violation=true + known AI crawler -> CRITICAL
 */
function calculateTrainpotSeverity(hpData: any): SeverityIndicator {
  if (!hpData || typeof hpData !== 'object') {
    return getDefaultSeverity(hpData);
  }

  const violation = hpData.violation;
  if (violation === false || violation === undefined) {
    return {
      level: SeverityLevel.LOW,
      score: 0.0,
      color: getSeverityColor(SeverityLevel.LOW),
      label: getSeverityLabel(SeverityLevel.LOW),
      description: "Compliant crawler - no violations"
    };
  }

  if (violation === true) {
    const userAgent = hpData.user_agent ?? hpData.userAgent ?? '';
    const isKnownAI = isKnownAICrawler(userAgent);
    const level = isKnownAI ? SeverityLevel.CRITICAL : SeverityLevel.HIGH;
    const score = isKnownAI ? 0.8 : 0.6;

    return {
      level,
      score,
      color: getSeverityColor(level),
      label: getSeverityLabel(level),
      description: generateTrainpotDescription(hpData, level)
    };
  }

  return getDefaultSeverity(hpData);
}

const KNOWN_AI_CRAWLER_PATTERNS = [
  "GPTBot",
  "Claude-Web",
  "ClaudeBot",
  "Google-Extended",
  "CCBot",
  "PerplexityBot",
  "Bytespider",
  "Applebot-Extended",
  "anthropic-ai",
  "cohere-ai",
  "FacebookBot",
  "Meta-ExternalAgent",
  "Omgilibot",
  "Diffbot",
  "YouBot",
  "Amazonbot",
  "Grok-bot",
  "ChatGPT-User"
];

function isKnownAICrawler(userAgent: string): boolean {
  if (!userAgent || typeof userAgent !== 'string') {
    return false;
  }
  const ua = userAgent.toLowerCase();
  return KNOWN_AI_CRAWLER_PATTERNS.some((pattern) =>
    ua.includes(pattern.toLowerCase())
  );
}

function generateTrainpotDescription(hpData: any, level: SeverityLevel): string {
  if (level === SeverityLevel.CRITICAL) {
    return "Scraper violation - known AI crawler";
  }
  return "Scraper violation detected";
}

/**
 * DEFAULT SEVERITY FOR EXISTING HONEYPOTS
 * This maintains the current behavior for dionaea, conpot, amun, etc.
 * These honeypots cannot be updated, so they get minimal severity indication
 */
function getDefaultSeverity(hpData: any): SeverityIndicator {
  // Existing honeypots (dionaea, conpot, amun, etc.) get LOW severity
  // This matches current behavior where they show minimal visual indicator
  return {
    level: SeverityLevel.LOW,
    score: 0.0,
    color: getSeverityColor(SeverityLevel.LOW),
    label: "Low",
    description: "Standard honeypot activity"
  };
}

/**
 * HONEYGO SEVERITY CALCULATOR
 * Only used for honeygo (app === "synsor") messages
 * This is the NEW logic for scan-based detection
 */
function calculateHoneygoSeverity(hpData: any): SeverityIndicator {
  if (!hpData || typeof hpData !== 'object') {
    return getDefaultSeverity(hpData);
  }

  // Priority 1: Use danger_level if available (check both snake_case and camelCase)
  const dangerLevel = hpData.danger_level ?? hpData.dangerLevel;
  if (dangerLevel !== undefined && typeof dangerLevel === 'number') {
    return getSeverityFromDangerLevel(dangerLevel);
  }

  // Priority 2: Use confidence score as baseline
  let baseScore = typeof hpData.confidence === 'number' ? hpData.confidence : 0.5;
  let level = SeverityLevel.LOW;

  // Priority 3: Boost based on Nmap detection
  if (hpData.is_nmap === true) {
    baseScore += 0.3;
    level = SeverityLevel.MEDIUM;
  }

  // Priority 4: Boost based on scan type
  const scanTypeBoost = getScanTypeBoost(hpData.scan_type);
  baseScore += scanTypeBoost.value;
  if (scanTypeBoost.level > level) {
    level = scanTypeBoost.level;
  }

  // Priority 5: Boost based on total events (packet count)
  const eventBoost = getEventCountBoost(hpData.total_events);
  baseScore += eventBoost.value;
  if (eventBoost.level > level) {
    level = eventBoost.level;
  }

  // Priority 6: Boost based on protocol type
  const protocolBoost = getProtocolBoost(hpData.transport, hpData.con_type);
  baseScore += protocolBoost.value;
  if (protocolBoost.level > level) {
    level = protocolBoost.level;
  }

  // Cap score at 1.0
  const finalScore = Math.min(baseScore, 1.0);

  // Map to severity level
  const finalLevel = mapScoreToSeverityLevel(finalScore, level);

  return {
    level: finalLevel,
    score: finalScore,
    color: getSeverityColor(finalLevel),
    label: getSeverityLabel(finalLevel),
    description: generateHoneygoDescription(hpData, finalLevel)
  };
}

// Map PSAD-style danger levels (1-5) to severity levels
function getSeverityFromDangerLevel(dangerLevel: number): SeverityIndicator {
  const levelMap: Record<number, SeverityLevel> = {
    1: SeverityLevel.LOW,      // 5 packets
    2: SeverityLevel.MEDIUM,   // 15 packets
    3: SeverityLevel.HIGH,     // 150 packets
    4: SeverityLevel.CRITICAL, // 1500 packets
    5: SeverityLevel.EXTREME   // 10000 packets
  };

  const level = levelMap[dangerLevel] || SeverityLevel.LOW;
  const score = dangerLevel / 5; // Normalize to 0-1

  return {
    level,
    score,
    color: getSeverityColor(level),
    label: `Danger Level ${dangerLevel}`,
    description: `Threat danger level ${dangerLevel} (${getDangerLevelDescription(dangerLevel)})`
  };
}

function getDangerLevelDescription(dangerLevel: number): string {
  const descriptions: Record<number, string> = {
    1: "Low activity (5+ packets)",
    2: "Moderate activity (15+ packets)",
    3: "High activity (150+ packets)",
    4: "Very high activity (1500+ packets)",
    5: "Extreme activity (10000+ packets)"
  };
  return descriptions[dangerLevel] || "Unknown";
}

function getScanTypeBoost(scanType: string): { value: number; level: SeverityLevel } {
  if (!scanType || typeof scanType !== 'string') {
    return { value: 0.0, level: SeverityLevel.LOW };
  }

  const boosts: Record<string, { value: number; level: SeverityLevel }> = {
    // High severity scan types
    "nmap_syn_scan": { value: 0.2, level: SeverityLevel.HIGH },
    "nmap_stealth_scan": { value: 0.2, level: SeverityLevel.HIGH },
    "nmap_port_scan": { value: 0.15, level: SeverityLevel.MEDIUM },
    "nmap_icmp_scan": { value: 0.15, level: SeverityLevel.MEDIUM },
    "nmap_high_frequency_scan": { value: 0.25, level: SeverityLevel.HIGH },
    "nmap_host_discovery": { value: 0.1, level: SeverityLevel.MEDIUM },

    // Medium severity scan types
    "syn_scan": { value: 0.1, level: SeverityLevel.MEDIUM },
    "tcp_connect_scan": { value: 0.1, level: SeverityLevel.MEDIUM },
    "connect_scan": { value: 0.1, level: SeverityLevel.MEDIUM },
    "icmp_scan": { value: 0.05, level: SeverityLevel.LOW },
    "udp_scan": { value: 0.05, level: SeverityLevel.LOW },

    // Low severity
    "icmp_ping": { value: 0.0, level: SeverityLevel.LOW },
    "tcp_connection": { value: 0.0, level: SeverityLevel.LOW },
    "reconnaissance": { value: 0.05, level: SeverityLevel.LOW }
  };

  return boosts[scanType] || { value: 0.0, level: SeverityLevel.LOW };
}

function getEventCountBoost(totalEvents: number): { value: number; level: SeverityLevel } {
  if (!totalEvents || typeof totalEvents !== 'number' || totalEvents === 0) {
    return { value: 0.0, level: SeverityLevel.LOW };
  }

  // PSAD-style thresholds
  if (totalEvents >= 10000) {
    return { value: 0.3, level: SeverityLevel.EXTREME };
  } else if (totalEvents >= 1500) {
    return { value: 0.25, level: SeverityLevel.CRITICAL };
  } else if (totalEvents >= 150) {
    return { value: 0.2, level: SeverityLevel.HIGH };
  } else if (totalEvents >= 15) {
    return { value: 0.1, level: SeverityLevel.MEDIUM };
  } else if (totalEvents >= 5) {
    return { value: 0.05, level: SeverityLevel.LOW };
  }

  return { value: 0.0, level: SeverityLevel.LOW };
}

function getProtocolBoost(transport: string, conType: string): { value: number; level: SeverityLevel } {
  // TCP scans are generally more concerning than UDP/ICMP
  if (transport === "tcp") {
    if (conType === "tcp_syn" || conType === "tcp_connection") {
      return { value: 0.1, level: SeverityLevel.MEDIUM };
    }
  } else if (transport === "icmp") {
    // ICMP scans are less concerning unless they're Nmap scans
    return { value: 0.0, level: SeverityLevel.LOW };
  }

  return { value: 0.0, level: SeverityLevel.LOW };
}

function mapScoreToSeverityLevel(score: number, baseLevel: SeverityLevel): SeverityLevel {
  // If we have a high base level, respect it
  if (baseLevel >= SeverityLevel.HIGH) {
    return baseLevel;
  }

  // Otherwise map score to level
  if (score >= 0.8) return SeverityLevel.EXTREME;
  if (score >= 0.6) return SeverityLevel.CRITICAL;
  if (score >= 0.4) return SeverityLevel.HIGH;
  if (score >= 0.2) return SeverityLevel.MEDIUM;
  return SeverityLevel.LOW;
}

function generateHoneygoDescription(hpData: any, level: SeverityLevel): string {
  const parts: string[] = [];

  const dangerLevel = hpData.danger_level ?? hpData.dangerLevel;
  if (dangerLevel !== undefined) {
    parts.push(`Danger Level ${dangerLevel}`);
  }

  if (hpData.is_nmap) {
    parts.push(`Nmap: ${hpData.nmap_type || "detected"}`);
  }

  if (hpData.scan_type) {
    parts.push(`Scan: ${hpData.scan_type}`);
  }

  if (hpData.total_events) {
    parts.push(`${hpData.total_events} events`);
  }

  if (hpData.confidence) {
    parts.push(`${Math.round(hpData.confidence * 100)}% confidence`);
  }

  return parts.join(" • ") || "Honeygo scan detection";
}

// Shared utility functions
function getSeverityColor(level: SeverityLevel): string {
  const colors: Record<SeverityLevel, string> = {
    [SeverityLevel.LOW]: "#22c55e",      // green-500
    [SeverityLevel.MEDIUM]: "#eab308",  // yellow-500
    [SeverityLevel.HIGH]: "#f97316",     // orange-500
    [SeverityLevel.CRITICAL]: "#ef4444", // red-500
    [SeverityLevel.EXTREME]: "#991b1b"   // red-800
  };
  return colors[level];
}

function getSeverityLabel(level: SeverityLevel): string {
  const labels: Record<SeverityLevel, string> = {
    [SeverityLevel.LOW]: "Low",
    [SeverityLevel.MEDIUM]: "Medium",
    [SeverityLevel.HIGH]: "High",
    [SeverityLevel.CRITICAL]: "Critical",
    [SeverityLevel.EXTREME]: "Extreme"
  };
  return labels[level];
}

