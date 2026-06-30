/**
 * Configuration Debugging Utilities
 * 
 * Tools for debugging and validating configuration parsing and generation
 */

import { ParsedStoreConfig } from './store-config-parser';
import { ServiceConfig as DynamicServiceConfig } from './dynamic-service-generator';
import { debugLog, debugGroup, debugGroupEnd, debugWarn } from './debug';

export interface DebugInfo {
    timestamp: string;
    honeypotType: string;
    hasStoreConfig: boolean;
    storeConfigValid: boolean;
    validationErrors: string[];
    parsedConfig: ParsedStoreConfig | null;
    generatedServices: DynamicServiceConfig[];
    finalConfig: Record<string, { enabled: boolean; port: string }>;
    fallbackUsed: boolean;
    fallbackReason?: string;
}

/**
 * Log configuration parsing steps with detailed information
 */
export function logConfigurationSteps(
    honeypotType: string,
    storeConfig: any,
    parsedConfig: ParsedStoreConfig | null,
    generatedServices: DynamicServiceConfig[],
    finalConfig: Record<string, { enabled: boolean; port: string }>,
    fallbackUsed: boolean = false,
    fallbackReason?: string
): DebugInfo {
    const debugInfo: DebugInfo = {
        timestamp: new Date().toISOString(),
        honeypotType,
        hasStoreConfig: !!storeConfig,
        storeConfigValid: false,
        validationErrors: [],
        parsedConfig,
        generatedServices,
        finalConfig,
        fallbackUsed,
        fallbackReason
    };

    // Validate store configuration
    if (storeConfig) {
        try {
            const { validateStoreConfiguration } = require('./store-config-parser');
            const validation = validateStoreConfiguration(storeConfig);
            debugInfo.storeConfigValid = validation.isValid;
            debugInfo.validationErrors = validation.errors;
        } catch (error) {
            debugInfo.validationErrors.push(`Validation error: ${error}`);
        }
    }

    // Log detailed information
    debugGroup(`🔍 Configuration Debug: ${honeypotType}`);
    debugLog('📊 Debug Info:', debugInfo);

    if (storeConfig) {
        debugLog('📦 Store Config:', storeConfig);
    } else {
        debugLog('⚠️ No store configuration provided');
    }

    if (parsedConfig) {
        debugLog('🔧 Parsed Config:', parsedConfig);
    }

    debugLog('⚙️ Generated Services:', generatedServices);
    debugLog('🎯 Final Config:', finalConfig);

    if (fallbackUsed) {
        debugWarn(`🔄 Fallback used: ${fallbackReason}`);
    }

    debugGroupEnd();

    return debugInfo;
}

/**
 * Validate configuration structure
 */
export function validateConfigurationStructure(config: any): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!config || typeof config !== 'object') {
        errors.push('Configuration must be an object');
        return { isValid: false, errors };
    }

    // Check for required fields in service configurations
    Object.entries(config).forEach(([serviceName, serviceConfig]) => {
        if (typeof serviceConfig !== 'object' || serviceConfig === null) {
            errors.push(`Service ${serviceName}: must be an object`);
            return;
        }

        if (!('enabled' in serviceConfig)) {
            errors.push(`Service ${serviceName}: missing 'enabled' field`);
        } else if (typeof serviceConfig.enabled !== 'boolean') {
            errors.push(`Service ${serviceName}: 'enabled' must be a boolean`);
        }

        if (!('port' in serviceConfig)) {
            errors.push(`Service ${serviceName}: missing 'port' field`);
        } else {
            const port = parseInt((serviceConfig as any).port);
            if (isNaN(port) || port < 1 || port > 65535) {
                errors.push(`Service ${serviceName}: 'port' must be a valid port number (1-65535)`);
            }
        }
    });

    return {
        isValid: errors.length === 0,
        errors
    };
}

/**
 * Provide detailed error messages for configuration issues
 */
export function getDetailedErrorMessage(error: any, context: string): string {
    let message = `Configuration error in ${context}: `;

    if (error instanceof Error) {
        message += error.message;
    } else if (typeof error === 'string') {
        message += error;
    } else {
        message += 'Unknown error occurred';
    }

    // Add common troubleshooting tips
    message += '\n\nTroubleshooting tips:';
    message += '\n- Check that the honeypot type is valid';
    message += '\n- Verify store configuration has required fields';
    message += '\n- Ensure port numbers are within valid range (1-65535)';
    message += '\n- Check browser console for detailed error logs';

    return message;
}

/**
 * Compare configurations and highlight differences
 */
export function compareConfigurations(
    config1: Record<string, { enabled: boolean; port: string }>,
    config2: Record<string, { enabled: boolean; port: string }>
): {
    added: string[];
    removed: string[];
    modified: Array<{
        service: string;
        field: string;
        oldValue: any;
        newValue: any;
    }>;
} {
    const added: string[] = [];
    const removed: string[] = [];
    const modified: Array<{
        service: string;
        field: string;
        oldValue: any;
        newValue: any;
    }> = [];

    // Find added services
    Object.keys(config2).forEach(service => {
        if (!(service in config1)) {
            added.push(service);
        }
    });

    // Find removed services
    Object.keys(config1).forEach(service => {
        if (!(service in config2)) {
            removed.push(service);
        }
    });

    // Find modified services
    Object.keys(config1).forEach(service => {
        if (service in config2) {
            const oldConfig = config1[service];
            const newConfig = config2[service];

            if (oldConfig.enabled !== newConfig.enabled) {
                modified.push({
                    service,
                    field: 'enabled',
                    oldValue: oldConfig.enabled,
                    newValue: newConfig.enabled
                });
            }

            if (oldConfig.port !== newConfig.port) {
                modified.push({
                    service,
                    field: 'port',
                    oldValue: oldConfig.port,
                    newValue: newConfig.port
                });
            }
        }
    });

    return { added, removed, modified };
}

/**
 * Generate configuration summary for debugging
 */
export function generateConfigurationSummary(
    honeypotType: string,
    config: Record<string, { enabled: boolean; port: string }>
): string {
    const enabledServices = Object.entries(config)
        .filter(([_, serviceConfig]) => serviceConfig.enabled)
        .map(([service, config]) => `${service}:${config.port}`);

    const disabledServices = Object.entries(config)
        .filter(([_, serviceConfig]) => !serviceConfig.enabled)
        .map(([service]) => service);

    let summary = `Configuration Summary for ${honeypotType}:\n`;
    summary += `- Total services: ${Object.keys(config).length}\n`;
    summary += `- Enabled services: ${enabledServices.length} (${enabledServices.join(', ')})\n`;
    summary += `- Disabled services: ${disabledServices.length} (${disabledServices.join(', ')})`;

    return summary;
}

/**
 * Debug configuration loading process
 */
export function debugConfigurationLoading(
    honeypotType: string,
    storeConfig: any,
    step: string,
    data?: any
): void {
    debugGroup(`🔍 Config Loading Debug: ${step}`);
    debugLog('Honeypot Type:', honeypotType);
    debugLog('Has Store Config:', !!storeConfig);

    if (data) {
        debugLog('Step Data:', data);
    }

    debugGroupEnd();
}
