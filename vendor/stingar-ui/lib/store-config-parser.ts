/**
 * HP App Store Configuration Parser
 * 
 * Utility functions to parse and extract configuration data from HP App Store
 * honeypot metadata for use in the stingarui deployment interface.
 */

export interface PortMapping {
    protocol: string;
    port: number;
    external?: number;
    internal?: number;
}

export interface ParsedStoreConfig {
    ports: PortMapping[];
    protocols: string[];
    configuration: Record<string, any>;
    schema?: any;
}

/**
 * Extract port mappings from HP App Store configuration
 */
export function extractPortsFromStoreConfig(storeConfig: any): PortMapping[] {
    const ports: PortMapping[] = [];

    if (!storeConfig) {
        return ports;
    }

    // Extract from default_configuration
    if (storeConfig.default_configuration && typeof storeConfig.default_configuration === 'object') {
        Object.entries(storeConfig.default_configuration).forEach(([key, value]) => {
            if (key.endsWith('_port') && typeof value === 'number') {
                const protocol = key.replace('_port', '');
                ports.push({
                    protocol,
                    port: value,
                    external: value,
                    internal: value
                });
            }
        });
    }

    // Extract from default_ports array
    if (storeConfig.default_ports && Array.isArray(storeConfig.default_ports)) {
        storeConfig.default_ports.forEach((port: number, index: number) => {
            // Try to match with supported_protocols
            if (storeConfig.supported_protocols && Array.isArray(storeConfig.supported_protocols)) {
                const protocol = storeConfig.supported_protocols[index];
                if (protocol) {
                    ports.push({
                        protocol,
                        port,
                        external: port,
                        internal: port
                    });
                }
            }
        });
    }

    // Extract from configuration_schema
    if (storeConfig.configuration_schema && storeConfig.configuration_schema.properties) {
        Object.entries(storeConfig.configuration_schema.properties).forEach(([key, schema]: [string, any]) => {
            if (key.endsWith('_port') && schema.default && typeof schema.default === 'number') {
                const protocol = key.replace('_port', '');
                // Check if we already have this protocol
                if (!ports.find(p => p.protocol === protocol)) {
                    ports.push({
                        protocol,
                        port: schema.default,
                        external: schema.default,
                        internal: schema.default
                    });
                }
            }
        });
    }

    return ports;
}

/**
 * Extract protocol names from HP App Store configuration
 */
export function extractProtocolsFromStoreConfig(storeConfig: any): string[] {
    const protocols: string[] = [];

    if (!storeConfig) {
        return protocols;
    }

    // Extract from supported_protocols
    if (storeConfig.supported_protocols && Array.isArray(storeConfig.supported_protocols)) {
        protocols.push(...storeConfig.supported_protocols);
    }

    // Extract from default_configuration keys
    if (storeConfig.default_configuration && typeof storeConfig.default_configuration === 'object') {
        Object.keys(storeConfig.default_configuration).forEach(key => {
            if (key.endsWith('_port')) {
                const protocol = key.replace('_port', '');
                if (!protocols.includes(protocol)) {
                    protocols.push(protocol);
                }
            }
        });
    }

    // Extract from configuration_schema
    if (storeConfig.configuration_schema && storeConfig.configuration_schema.properties) {
        Object.keys(storeConfig.configuration_schema.properties).forEach(key => {
            if (key.endsWith('_port')) {
                const protocol = key.replace('_port', '');
                if (!protocols.includes(protocol)) {
                    protocols.push(protocol);
                }
            }
        });
    }

    return protocols;
}

/**
 * Check if a value contains dangerous command patterns
 */
function containsDangerousCommands(value: any): boolean {
    if (typeof value !== 'string') {
        return false;
    }
    
    const dangerousPatterns = [
        /cmd\s*[/\\]c/i,
        /powershell/i,
        /bash\s+-c/i,
        /sh\s+-c/i,
        /base64\s+-d/i,
        /eval\s*\(/i,
        /exec\s*\(/i,
        /subprocess/i,
        /os\.system/i,
        /os\.popen/i,
        /\|\s*base64/i,
        /\|\s*sh\s*$/i,
        /\|\s*bash\s*$/i,
        /curl.*http/i,
        /wget.*http/i,
    ];
    
    return dangerousPatterns.some(pattern => pattern.test(value));
}

/**
 * Check if a key name suggests it might contain executable commands
 */
function isDangerousKey(key: string): boolean {
    const dangerousKeys = [
        'test',
        'command',
        'cmd',
        'exec',
        'script',
        'shell',
        'eval',
        'run',
        'execute',
    ];
    
    const lowerKey = key.toLowerCase();
    return dangerousKeys.some(dk => lowerKey.includes(dk));
}

/**
 * Parse default configuration from HP App Store
 * Sanitizes input to prevent command injection
 */
export function parseDefaultConfiguration(defaultConfig: any): Record<string, any> {
    if (!defaultConfig || typeof defaultConfig !== 'object') {
        return {};
    }

    const parsed: Record<string, any> = {};

    Object.entries(defaultConfig).forEach(([key, value]) => {
        // Skip dangerous keys that might contain executable commands
        if (isDangerousKey(key)) {
            console.warn(`Skipping potentially dangerous configuration key: ${key}`);
            return;
        }
        
        // Skip values that contain dangerous command patterns
        if (containsDangerousCommands(value)) {
            console.warn(`Skipping configuration value with dangerous commands for key: ${key}`);
            return;
        }
        
        // Convert port configurations to enabled/port format
        if (key.endsWith('_port') && typeof value === 'number') {
            const protocol = key.replace('_port', '');
            parsed[`${protocol}_enabled`] = true;
            parsed[`${protocol}_port`] = value;
        } else if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
            // Only allow safe scalar values (strings, numbers, booleans)
            // Reject objects, arrays, and functions
            parsed[key] = value;
        } else {
            // Skip complex types (objects, arrays) that might contain nested commands
            console.warn(`Skipping non-scalar configuration value for key: ${key} (type: ${typeof value})`);
        }
    });

    return parsed;
}

/**
 * Parse complete HP App Store configuration
 */
export function parseStoreConfiguration(storeConfig: any): ParsedStoreConfig {
    if (!storeConfig) {
        return {
            ports: [],
            protocols: [],
            configuration: {}
        };
    }

    const ports = extractPortsFromStoreConfig(storeConfig);
    const protocols = extractProtocolsFromStoreConfig(storeConfig);
    const configuration = parseDefaultConfiguration(storeConfig.default_configuration);

    return {
        ports,
        protocols,
        configuration,
        schema: storeConfig.configuration_schema
    };
}

/**
 * Convert parsed store config to dynamic honeypot config format
 */
export function convertToDynamicConfig(parsedConfig: ParsedStoreConfig): Record<string, { enabled: boolean; port: string }> {
    const dynamicConfig: Record<string, { enabled: boolean; port: string }> = {};

    // Use ports array as primary source
    parsedConfig.ports.forEach(portMapping => {
        dynamicConfig[portMapping.protocol] = {
            enabled: true,
            port: portMapping.port.toString()
        };
    });

    // Fallback to protocols if no ports found
    if (parsedConfig.ports.length === 0 && parsedConfig.protocols.length > 0) {
        parsedConfig.protocols.forEach(protocol => {
            // Use common default ports
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
                'vnc': 5900
            };

            dynamicConfig[protocol] = {
                enabled: true,
                port: (defaultPorts[protocol] || 8080).toString()
            };
        });
    }

    return dynamicConfig;
}

/**
 * Validate store configuration structure
 * Also checks for dangerous command patterns
 */
export function validateStoreConfiguration(storeConfig: any): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!storeConfig) {
        errors.push('Store configuration is null or undefined');
        return { isValid: false, errors };
    }

    if (typeof storeConfig !== 'object') {
        errors.push('Store configuration must be an object');
        return { isValid: false, errors };
    }

    // Check for required fields
    if (!storeConfig.hp_type) {
        errors.push('Missing required field: hp_type');
    }

    if (!storeConfig.name) {
        errors.push('Missing required field: name');
    }

    // Validate configuration structure
    if (storeConfig.default_configuration && typeof storeConfig.default_configuration !== 'object') {
        errors.push('default_configuration must be an object');
    }

    if (storeConfig.supported_protocols && !Array.isArray(storeConfig.supported_protocols)) {
        errors.push('supported_protocols must be an array');
    }

    if (storeConfig.default_ports && !Array.isArray(storeConfig.default_ports)) {
        errors.push('default_ports must be an array');
    }

    // Security check: Scan default_configuration for dangerous commands
    if (storeConfig.default_configuration && typeof storeConfig.default_configuration === 'object') {
        Object.entries(storeConfig.default_configuration).forEach(([key, value]) => {
            if (isDangerousKey(key)) {
                errors.push(`Potentially dangerous configuration key detected: ${key}`);
            }
            if (containsDangerousCommands(value)) {
                errors.push(`Dangerous command pattern detected in configuration key: ${key}`);
            }
        });
    }

    return {
        isValid: errors.length === 0,
        errors
    };
}
