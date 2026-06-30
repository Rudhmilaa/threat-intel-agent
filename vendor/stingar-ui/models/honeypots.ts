/**
 * Honeypots configuration models
 * 
 * To add a new honeypot, follow these steps:
 * 1. Add new {Honeypot}Config type
 * 2. Update HoneypotConfigType with the new type
 * 3. Add the new name to HoneypotType
 * 4. Add the new config to DEFAULT_CONFIGS
 * 5. Add a new card to HONEYPOT_CARDS
 * 
 */


export type ServiceConfig = {
  enabled: boolean;
  port: string;
};
export type BaseHoneypotConfig = {
  name: string;
  hp_type: string;
  hp_options: Record<string, any>;
};
export type CowrieConfig = {
  ssh: ServiceConfig;
  telnet: ServiceConfig;
};
export type DionaeaConfig = {
  ftp: ServiceConfig;
  http: ServiceConfig;
  mqtt: ServiceConfig;
  mssql: ServiceConfig;
  mysql: ServiceConfig;
  pptp: ServiceConfig;
  sip: ServiceConfig;
  smb: ServiceConfig;
  tftp: ServiceConfig;
  upnp: ServiceConfig;
};
export type AmunConfig = {
  smb: ServiceConfig;
  rdp: ServiceConfig;
};
export type ConpotConfig = {
  http: ServiceConfig;
  s7: ServiceConfig;
  modbus: ServiceConfig;
  snmp: ServiceConfig;
  bacnet: ServiceConfig;
  ipmi: ServiceConfig;
  ftp: ServiceConfig;
  tftp: ServiceConfig;
  enip: ServiceConfig;
};
export type GlastopfConfig = {
  web: ServiceConfig;
};
export type RdphoneyConfig = {
  rdp: ServiceConfig;
};

export type HoneypotConfigType =
  | CowrieConfig
  | DionaeaConfig
  | AmunConfig
  | ConpotConfig
  | GlastopfConfig
  | RdphoneyConfig;

export type HoneypotType = 'cowrie' | 'dionaea' | 'amun' | 'conpot' | 'glastopf' | 'rdphoney' | string;

// Legacy default configurations - now handled by dynamic system
// These are kept for backward compatibility but should not be used for new honeypots
export const LEGACY_DEFAULT_CONFIGS: Record<string, HoneypotConfigType> = {
  cowrie: {
    ssh: { enabled: true, port: "22" },
    telnet: { enabled: true, port: "23" }
  },
  dionaea: {
    ftp: { enabled: true, port: "21" },
    http: { enabled: true, port: "80" },
    mqtt: { enabled: true, port: "1883" },
    mssql: { enabled: true, port: "1433" },
    mysql: { enabled: true, port: "3306" },
    pptp: { enabled: true, port: "1723" },
    sip: { enabled: true, port: "5060" },
    smb: { enabled: true, port: "445" },
    tftp: { enabled: true, port: "69" },
    upnp: { enabled: true, port: "1900" }
  },
  amun: {
    smb: { enabled: true, port: "445" },
    rdp: { enabled: true, port: "3389" }
  },
  conpot: {
    http: { enabled: true, port: "80" },
    s7: { enabled: true, port: "102" },
    modbus: { enabled: true, port: "502" },
    snmp: { enabled: true, port: "161" },
    bacnet: { enabled: true, port: "47808" },
    ipmi: { enabled: true, port: "623" },
    ftp: { enabled: true, port: "21" },
    tftp: { enabled: true, port: "69" },
    enip: { enabled: true, port: "44818" }
  },
  glastopf: {
    web: { enabled: true, port: "80" }
  },
  rdphoney: {
    rdp: { enabled: true, port: "3389" }
  }
};

// Deprecated: Use dynamic configuration system instead
export const DEFAULT_CONFIGS = LEGACY_DEFAULT_CONFIGS;

// DEPRECATED: Function to get configuration for any honeypot type
// Use the dynamic configuration system instead (generateDefaultConfig from honeypot-registry)
export const getHoneypotConfig = (type: string): HoneypotConfigType => {
  console.warn('getHoneypotConfig is deprecated. Use generateDefaultConfig from honeypot-registry instead.');

  // Safety check for type parameter
  if (!type || typeof type !== 'string') {
    console.warn('getHoneypotConfig: Invalid type parameter:', type);
    return LEGACY_DEFAULT_CONFIGS.cowrie;
  }

  // If it's a known type, return the legacy config
  if (type in LEGACY_DEFAULT_CONFIGS) {
    return LEGACY_DEFAULT_CONFIGS[type];
  }

  // For store configurations, try to map to base type
  if (type.startsWith('cowrie')) return LEGACY_DEFAULT_CONFIGS.cowrie;
  if (type.startsWith('dionaea')) return LEGACY_DEFAULT_CONFIGS.dionaea;
  if (type.startsWith('amun')) return LEGACY_DEFAULT_CONFIGS.amun;
  if (type.startsWith('conpot')) return LEGACY_DEFAULT_CONFIGS.conpot;
  if (type.startsWith('glastopf')) return LEGACY_DEFAULT_CONFIGS.glastopf;
  if (type.startsWith('rdphoney')) return LEGACY_DEFAULT_CONFIGS.rdphoney;

  // Default fallback
  return LEGACY_DEFAULT_CONFIGS.cowrie;
};

export const HONEYPOT_CARDS: Array<{ title: string, type: HoneypotType, description: string }> = [
  {
    title: "Cowrie",
    type: "cowrie",
    description: "Cowrie is a medium interaction SSH and Telnet honeypot designed to log brute force attacks and the shell interaction performed by the attacker."
  },
  {
    title: "Dionaea",
    type: "dionaea",
    description: "Dionaea aims to trap malware exploiting vulnerabilities exposed by services offered over a network, and ultimately obtain a copy of the malware."
  },
  {
    title: "Amun",
    type: "amun",
    description: "Amun is a low-interaction honeypot, designed to capture autonomous spreading malware in an automated fashion."
  },
  {
    title: "Conpot",
    type: "conpot",
    description: "Conpot is an industrial control system (ICS) honeypot designed to emulate complex industrial control systems."
  },
  {
    title: "Glastopf",
    type: "glastopf",
    description: "Glastopf is a web application honeypot designed to emulate vulnerabilities in web applications."
  },
  {
    title: "RDPHoney",
    type: "rdphoney",
    description: "RDPHoney is a low-interaction honeypot designed to detect and log RDP (Remote Desktop Protocol) brute force attacks."
  }
];