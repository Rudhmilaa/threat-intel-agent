/**
 * Dynamic Service Generator
 * 
 * Functions to generate service configurations from HP App Store metadata
 * for use in the stingarui deployment interface.
 */

import { PortMapping } from './store-config-parser';

export interface ServiceConfig {
    name: string;
    enabled: boolean;
    port: string;
    description?: string;
    defaultPort?: number;
}

/**
 * Generate service configurations from port mappings
 */
export function generateServicesFromPorts(ports: PortMapping[]): ServiceConfig[] {
    return ports.map(portMapping => ({
        name: portMapping.protocol,
        enabled: true,
        port: portMapping.port.toString(),
        description: `${portMapping.protocol.toUpperCase()} service`,
        defaultPort: portMapping.port
    }));
}

/**
 * Generate service configurations from protocol names
 */
export function generateServicesFromProtocols(protocols: string[]): ServiceConfig[] {
    const defaultPorts: Record<string, number> = {
        'ssh': 22,
        'telnet': 23,
        'ftp': 21,
        'http': 80,
        'https': 443,
        'smtp': 25,
        'pop3': 110,
        'imap': 143,
        'rdp': 3389,
        'vnc': 5900,
        'mqtt': 1883,
        'mssql': 1433,
        'mysql': 3306,
        'pptp': 1723,
        'sip': 5060,
        'smb': 445,
        'tftp': 69,
        'upnp': 1900,
        's7': 102,
        'modbus': 502,
        'snmp': 161,
        'bacnet': 47808,
        'ipmi': 623,
        'enip': 44818
    };

    return protocols.map(protocol => ({
        name: protocol,
        enabled: true,
        port: (defaultPorts[protocol] || 8080).toString(),
        description: `${protocol.toUpperCase()} service`,
        defaultPort: defaultPorts[protocol] || 8080
    }));
}

/**
 * Merge port and protocol configurations
 */
export function mergePortAndProtocolConfig(ports: PortMapping[], protocols: string[]): ServiceConfig[] {
    const portServices = generateServicesFromPorts(ports);
    const protocolServices = generateServicesFromProtocols(protocols);

    const merged: ServiceConfig[] = [];
    const seenProtocols = new Set<string>();

    // Add services from ports first (more specific)
    portServices.forEach(service => {
        merged.push(service);
        seenProtocols.add(service.name);
    });

    // Add services from protocols that weren't already added
    protocolServices.forEach(service => {
        if (!seenProtocols.has(service.name)) {
            merged.push(service);
            seenProtocols.add(service.name);
        }
    });

    return merged;
}

/**
 * Convert service configs to dynamic honeypot config format
 */
export function convertToDynamicConfig(services: ServiceConfig[]): Record<string, { enabled: boolean; port: string }> {
    const config: Record<string, { enabled: boolean; port: string }> = {};

    services.forEach(service => {
        config[service.name] = {
            enabled: service.enabled,
            port: service.port
        };
    });

    return config;
}

/**
 * Generate service configurations from store configuration object
 */
export function generateServicesFromStoreConfig(storeConfig: any): ServiceConfig[] {
    if (!storeConfig) {
        return [];
    }

    const services: ServiceConfig[] = [];

    // Extract from default_configuration
    if (storeConfig.default_configuration && typeof storeConfig.default_configuration === 'object') {
        Object.entries(storeConfig.default_configuration).forEach(([key, value]) => {
            if (key.endsWith('_port') && typeof value === 'number') {
                const protocol = key.replace('_port', '');
                services.push({
                    name: protocol,
                    enabled: true,
                    port: value.toString(),
                    description: `${protocol.toUpperCase()} service`,
                    defaultPort: value
                });
            }
        });
    }

    // Extract from supported_protocols if no services found
    if (services.length === 0 && storeConfig.supported_protocols && Array.isArray(storeConfig.supported_protocols)) {
        return generateServicesFromProtocols(storeConfig.supported_protocols);
    }

    return services;
}

/**
 * Validate service configurations
 */
export function validateServiceConfigs(services: ServiceConfig[]): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!Array.isArray(services)) {
        errors.push('Services must be an array');
        return { isValid: false, errors };
    }

    services.forEach((service, index) => {
        if (!service.name || typeof service.name !== 'string') {
            errors.push(`Service ${index}: name is required and must be a string`);
        }

        if (typeof service.enabled !== 'boolean') {
            errors.push(`Service ${index}: enabled must be a boolean`);
        }

        if (!service.port || typeof service.port !== 'string') {
            errors.push(`Service ${index}: port is required and must be a string`);
        } else {
            const portNum = parseInt(service.port);
            if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
                errors.push(`Service ${index}: port must be a valid port number (1-65535)`);
            }
        }
    });

    return {
        isValid: errors.length === 0,
        errors
    };
}

/**
 * Get unique service names from configurations
 */
export function getUniqueServiceNames(services: ServiceConfig[]): string[] {
    const names = new Set<string>();
    services.forEach(service => names.add(service.name));
    return Array.from(names);
}

/**
 * Filter services by enabled status
 */
export function filterEnabledServices(services: ServiceConfig[]): ServiceConfig[] {
    return services.filter(service => service.enabled);
}

/**
 * Sort services by name
 */
export function sortServicesByName(services: ServiceConfig[]): ServiceConfig[] {
    return [...services].sort((a, b) => a.name.localeCompare(b.name));
}
