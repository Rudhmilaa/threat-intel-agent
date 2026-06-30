/**
 * Dynamic Honeypot Registry System
 * 
 * This system allows for dynamic registration and management of honeypot types
 * without requiring code changes. It automatically adapts to new honeypot types
 * based on the configuration data received from the store.
 */

import { debugLog, debugGroup, debugGroupEnd } from './debug';

export interface HoneypotService {
    name: string;
    defaultPort: number;
    description?: string;
}

export interface HoneypotTypeDefinition {
    name: string;
    baseType: string;
    services: HoneypotService[];
    description: string;
    category: 'network' | 'web' | 'industrial' | 'malware' | 'custom';
    defaultEnabled: boolean;
}

export interface DynamicHoneypotConfig {
    [serviceName: string]: {
        enabled: boolean;
        port: string;
    };
}

// Registry for known honeypot types
const HONEYPOT_REGISTRY = new Map<string, HoneypotTypeDefinition>();

// Initialize with known types
const initializeRegistry = () => {
    // Cowrie family
    HONEYPOT_REGISTRY.set('cowrie', {
        name: 'Cowrie',
        baseType: 'cowrie',
        services: [
            { name: 'ssh', defaultPort: 22, description: 'SSH service' },
            { name: 'telnet', defaultPort: 23, description: 'Telnet service' }
        ],
        description: 'SSH and Telnet honeypot designed to log brute force attacks and shell interactions.',
        category: 'network',
        defaultEnabled: true
    });

    // Dionaea family
    HONEYPOT_REGISTRY.set('dionaea', {
        name: 'Dionaea',
        baseType: 'dionaea',
        services: [
            { name: 'ftp', defaultPort: 21, description: 'FTP service' },
            { name: 'http', defaultPort: 80, description: 'HTTP service' },
            { name: 'mqtt', defaultPort: 1883, description: 'MQTT service' },
            { name: 'mssql', defaultPort: 1433, description: 'Microsoft SQL Server' },
            { name: 'mysql', defaultPort: 3306, description: 'MySQL database' },
            { name: 'pptp', defaultPort: 1723, description: 'PPTP VPN' },
            { name: 'sip', defaultPort: 5060, description: 'SIP protocol' },
            { name: 'smb', defaultPort: 445, description: 'SMB file sharing' },
            { name: 'tftp', defaultPort: 69, description: 'TFTP service' },
            { name: 'upnp', defaultPort: 1900, description: 'UPnP service' }
        ],
        description: 'Multi-protocol honeypot designed to trap malware exploiting network vulnerabilities.',
        category: 'malware',
        defaultEnabled: true
    });


    // Conpot family
    HONEYPOT_REGISTRY.set('conpot', {
        name: 'Conpot',
        baseType: 'conpot',
        services: [
            { name: 'http', defaultPort: 80, description: 'HTTP service' },
            { name: 's7', defaultPort: 102, description: 'S7 protocol' },
            { name: 'modbus', defaultPort: 502, description: 'Modbus protocol' },
            { name: 'snmp', defaultPort: 161, description: 'SNMP protocol' },
            { name: 'bacnet', defaultPort: 47808, description: 'BACnet protocol' },
            { name: 'ipmi', defaultPort: 623, description: 'IPMI protocol' },
            { name: 'ftp', defaultPort: 21, description: 'FTP service' },
            { name: 'tftp', defaultPort: 69, description: 'TFTP service' },
            { name: 'enip', defaultPort: 44818, description: 'EtherNet/IP protocol' }
        ],
        description: 'Industrial control system (ICS) honeypot designed to emulate complex industrial systems.',
        category: 'industrial',
        defaultEnabled: true
    });


    // Amun family
    HONEYPOT_REGISTRY.set('amun', {
        name: 'Amun',
        baseType: 'amun',
        services: [
            { name: 'smb', defaultPort: 445, description: 'SMB file sharing' },
            { name: 'rdp', defaultPort: 3389, description: 'Remote Desktop Protocol' }
        ],
        description: 'Low-interaction honeypot designed to capture autonomous spreading malware.',
        category: 'malware',
        defaultEnabled: true
    });

    // Glastopf
    HONEYPOT_REGISTRY.set('glastopf', {
        name: 'Glastopf',
        baseType: 'glastopf',
        services: [
            { name: 'web', defaultPort: 80, description: 'Web application' }
        ],
        description: 'Web application honeypot designed to emulate web application vulnerabilities.',
        category: 'web',
        defaultEnabled: true
    });

    // RDPHoney family
    HONEYPOT_REGISTRY.set('rdphoney', {
        name: 'RDPHoney',
        baseType: 'rdphoney',
        services: [
            { name: 'rdp', defaultPort: 3389, description: 'Remote Desktop Protocol' }
        ],
        description: 'RDP honeypot designed to detect and log RDP brute force attacks.',
        category: 'network',
        defaultEnabled: true
    });

};

// Initialize the registry
initializeRegistry();

/**
 * Get honeypot type definition
 */
export function getHoneypotTypeDefinition(type: string): HoneypotTypeDefinition | null {
    if (!type) return null;

    // Direct match
    if (HONEYPOT_REGISTRY.has(type)) {
        return HONEYPOT_REGISTRY.get(type)!;
    }

    // Try to find by base type
    for (const [key, definition] of HONEYPOT_REGISTRY.entries()) {
        if (type.startsWith(definition.baseType)) {
            return definition;
        }
    }

    return null;
}

/**
 * Generate default configuration for a honeypot type
 */
export function generateDefaultConfig(type: string, storeConfig?: any): DynamicHoneypotConfig {
    debugLog(`Generating default config for type: ${type}`, { hasStoreConfig: !!storeConfig });

    // Fallback Chain 1: Use HP App Store configuration (primary)
    if (storeConfig) {
        debugLog(`Attempting to use HP App Store configuration for honeypot type: ${type}`);

        try {
            // Import the store config parser only when needed
            const { parseStoreConfiguration, convertToDynamicConfig, validateStoreConfiguration } = require('./store-config-parser');

            // Validate store configuration
            const validation = validateStoreConfiguration(storeConfig);
            if (validation.isValid) {
                // Parse store configuration
                const parsedConfig = parseStoreConfiguration(storeConfig);
                const dynamicConfig = convertToDynamicConfig(parsedConfig);

                if (Object.keys(dynamicConfig).length > 0) {
                    debugLog(`✅ Successfully generated dynamic config from HP App Store:`, dynamicConfig);
                    return dynamicConfig;
                } else {
                    console.warn(`⚠️ Store configuration parsed but no services found for ${type}`);
                }
            } else {
                console.warn(`⚠️ Invalid store configuration for ${type}:`, validation.errors);
            }
        } catch (error) {
            console.error(`❌ Error processing store configuration for ${type}:`, error);
        }
    }

    // Fallback Chain 2: Use registry definition for known types (secondary)
    const definition = getHoneypotTypeDefinition(type);
    if (definition) {
        debugLog(`✅ Using registry definition for known honeypot type: ${type}`);
        const config: DynamicHoneypotConfig = {};

        definition.services.forEach(service => {
            config[service.name] = {
                enabled: definition.defaultEnabled,
                port: service.defaultPort.toString()
            };
        });

        return config;
    }

    // Fallback Chain 3: Use generic default configuration (tertiary)
    console.warn(`⚠️ No definition found for honeypot type: ${type}, using generic fallback`);
    return {
        default: { enabled: true, port: "8080" }
    };
}

/**
 * Convert store configuration to dynamic honeypot config
 */
export function convertStoreConfigToDynamicConfig(
    storeOptions: Record<string, any>,
    type: string,
    fullStoreConfig?: any
): DynamicHoneypotConfig {
    debugLog("Converting store options to dynamic config:", storeOptions);

    // Safety check for storeOptions
    if (!storeOptions || typeof storeOptions !== 'object') {
        console.error("Invalid storeOptions:", storeOptions);
        return generateDefaultConfig(type, fullStoreConfig);
    }

    // Check if storeOptions is in the hp_options format (from database)
    const hasHpOptionsFormat = Object.keys(storeOptions).some(key =>
        key.endsWith('_enabled') || key.endsWith('_port')
    );

    if (hasHpOptionsFormat) {
        debugLog("Detected hp_options format, converting directly");
        const config: DynamicHoneypotConfig = {};

        // Parse hp_options format directly
        Object.entries(storeOptions).forEach(([key, value]) => {
            if (key.endsWith('_enabled')) {
                const serviceName = key.replace('_enabled', '');
                if (!config[serviceName]) {
                    config[serviceName] = { enabled: false, port: "0" };
                }
                config[serviceName].enabled = Boolean(value);
            } else if (key.endsWith('_port')) {
                const serviceName = key.replace('_port', '');
                if (!config[serviceName]) {
                    config[serviceName] = { enabled: true, port: "0" };
                }
                config[serviceName].port = value.toString();
            }
        });

        debugLog("Converted dynamic config from hp_options:", config);

        // Ensure we have at least one service configured
        if (Object.keys(config).length === 0) {
            console.warn("No services found in hp_options, using default");
            return generateDefaultConfig(type, fullStoreConfig);
        }

        return config;
    }

    // Fallback to original logic for other formats
    const definition = getHoneypotTypeDefinition(type);
    const config: DynamicHoneypotConfig = {};

    if (definition) {
        // Use definition to build config
        definition.services.forEach(service => {
            const enabledKey = `${service.name}_enabled`;
            const portKey = `${service.name}_port`;

            config[service.name] = {
                enabled: storeOptions[enabledKey] ?? definition.defaultEnabled,
                port: (storeOptions[portKey] ?? service.defaultPort).toString()
            };
        });
    } else {
        // Fallback: parse store options dynamically
        Object.entries(storeOptions).forEach(([key, value]) => {
            if (key.endsWith('_enabled')) {
                const serviceName = key.replace('_enabled', '');
                if (!config[serviceName]) {
                    config[serviceName] = { enabled: false, port: "0" };
                }
                config[serviceName].enabled = Boolean(value);
            } else if (key.endsWith('_port')) {
                const serviceName = key.replace('_port', '');
                if (!config[serviceName]) {
                    config[serviceName] = { enabled: true, port: "0" };
                }
                config[serviceName].port = value.toString();
            }
        });
    }

    debugLog("Converted dynamic config:", config);

    // Ensure we have at least one service configured
    if (Object.keys(config).length === 0) {
        console.warn("No services found in store options, using default");
        return generateDefaultConfig(type, fullStoreConfig);
    }

    return config;
}

/**
 * Get all registered honeypot types
 */
export function getAllHoneypotTypes(): HoneypotTypeDefinition[] {
    return Array.from(HONEYPOT_REGISTRY.values());
}

/**
 * Get honeypot types by category
 */
export function getHoneypotTypesByCategory(category: string): HoneypotTypeDefinition[] {
    return getAllHoneypotTypes().filter(type => type.category === category);
}

/**
 * Register a new honeypot type dynamically
 */
export function registerHoneypotType(
    type: string,
    definition: HoneypotTypeDefinition
): void {
    HONEYPOT_REGISTRY.set(type, definition);
    debugLog(`Registered new honeypot type: ${type}`);
}

/**
 * Check if a honeypot type is supported
 */
export function isHoneypotTypeSupported(type: string): boolean {
    return getHoneypotTypeDefinition(type) !== null;
}

/**
 * Get description for a honeypot type
 */
export function getHoneypotDescription(type: string): string {
    const definition = getHoneypotTypeDefinition(type);
    return definition?.description || `Custom honeypot configuration: ${type}`;
}

/**
 * Get category for a honeypot type
 */
export function getHoneypotCategory(type: string): string {
    const definition = getHoneypotTypeDefinition(type);
    return definition?.category || 'custom';
}
