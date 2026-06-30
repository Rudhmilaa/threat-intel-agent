/**
 * Configuration Testing Utilities
 * 
 * Test the dynamic configuration system with known honeypot types
 */

import { generateDefaultConfig, convertStoreConfigToDynamicConfig } from './honeypot-registry';
import { parseStoreConfiguration, validateStoreConfiguration } from './store-config-parser';
import { generateServicesFromStoreConfig } from './dynamic-service-generator';
import { logConfigurationSteps } from './debug-config';

// Test data for known honeypot types
export const KNOWN_HONEYPOT_TESTS = {
    cowrie: {
        name: 'Cowrie SSH Honeypot',
        storeConfig: {
            hp_type: 'cowrie',
            name: 'cowrie',
            supported_protocols: ['ssh'],
            default_ports: [2222],
            default_configuration: {
                ssh_port: 2222,
                log_level: 'INFO',
                max_attempts: 3
            },
            configuration_schema: {
                properties: {
                    ssh_port: { default: 2222, type: 'integer' },
                    log_level: { default: 'INFO', type: 'string' }
                }
            }
        },
        expectedServices: ['ssh'],
        expectedPorts: [2222]
    },
    dionaea: {
        name: 'Dionaea FTP Honeypot',
        storeConfig: {
            hp_type: 'dionaea',
            name: 'dionaea',
            supported_protocols: ['ftp', 'http', 'tftp'],
            default_ports: [21, 80, 69],
            default_configuration: {
                ftp_port: 21,
                http_port: 80,
                tftp_port: 69
            }
        },
        expectedServices: ['ftp', 'http', 'tftp'],
        expectedPorts: [21, 80, 69]
    },
    conpot: {
        name: 'Conpot ICS Honeypot',
        storeConfig: {
            hp_type: 'conpot',
            name: 'conpot',
            supported_protocols: ['modbus', 's7', 'enip'],
            default_ports: [502, 102, 44818],
            default_configuration: {
                modbus_port: 502,
                s7_port: 102,
                enip_port: 44818
            }
        },
        expectedServices: ['modbus', 's7', 'enip'],
        expectedPorts: [502, 102, 44818]
    }
};

// Test data for unknown honeypot types
export const UNKNOWN_HONEYPOT_TESTS = {
    p4: {
        name: 'P4 Custom Honeypot',
        storeConfig: {
            hp_type: 'p4',
            name: 'p4',
            supported_protocols: ['custom_protocol'],
            default_ports: [9999],
            default_configuration: {
                custom_protocol_port: 9999,
                custom_setting: 'value'
            }
        },
        expectedServices: ['custom_protocol'],
        expectedPorts: [9999]
    },
    custom_hp: {
        name: 'Custom Honeypot',
        storeConfig: {
            hp_type: 'custom_hp',
            name: 'custom_hp',
            supported_protocols: ['web', 'api'],
            default_ports: [8080, 9090],
            default_configuration: {
                web_port: 8080,
                api_port: 9090
            }
        },
        expectedServices: ['web', 'api'],
        expectedPorts: [8080, 9090]
    }
};

/**
 * Test configuration generation for known honeypot types
 */
export function testKnownHoneypotTypes(): void {
    console.group('🧪 Testing Known Honeypot Types');

    Object.entries(KNOWN_HONEYPOT_TESTS).forEach(([type, testData]) => {
        console.group(`Testing ${testData.name} (${type})`);

        try {
            // Test with store configuration
            const configWithStore = generateDefaultConfig(type, testData.storeConfig);
            console.log('✅ Config with store:', configWithStore);

            // Test without store configuration (fallback)
            const configWithoutStore = generateDefaultConfig(type);
            console.log('✅ Config without store:', configWithoutStore);

            // Validate expected services
            const hasExpectedServices = testData.expectedServices.every((service: string) =>
                configWithStore[service] && configWithStore[service].enabled
            );

            if (hasExpectedServices) {
                console.log('✅ All expected services found');
            } else {
                console.warn('⚠️ Missing expected services');
            }

                  // Validate expected ports
      const hasExpectedPorts = testData.expectedServices.every((service: string, index: number) => 
        configWithStore[service] && 
        parseInt(configWithStore[service].port) === testData.expectedPorts[index]
      );

            if (hasExpectedPorts) {
                console.log('✅ All expected ports match');
            } else {
                console.warn('⚠️ Port mismatch detected');
            }

        } catch (error) {
            console.error(`❌ Test failed for ${type}:`, error);
        }

        console.groupEnd();
    });

    console.groupEnd();
}

/**
 * Test configuration generation for unknown honeypot types
 */
export function testUnknownHoneypotTypes(): void {
    console.group('🧪 Testing Unknown Honeypot Types');

    Object.entries(UNKNOWN_HONEYPOT_TESTS).forEach(([type, testData]) => {
        console.group(`Testing ${testData.name} (${type})`);

        try {
            // Test with store configuration
            const configWithStore = generateDefaultConfig(type, testData.storeConfig);
            console.log('✅ Config with store:', configWithStore);

            // Test without store configuration (fallback)
            const configWithoutStore = generateDefaultConfig(type);
            console.log('✅ Config without store:', configWithoutStore);

                  // Validate that store config takes precedence
      const storeConfigUsed = testData.expectedServices.every((service: string) => 
        configWithStore[service] && configWithStore[service].enabled
      );

            if (storeConfigUsed) {
                console.log('✅ Store configuration used successfully');
            } else {
                console.warn('⚠️ Store configuration not used properly');
            }

            // Validate fallback behavior
            const fallbackUsed = configWithoutStore.default && configWithoutStore.default.enabled;
            if (fallbackUsed) {
                console.log('✅ Fallback configuration used');
            } else {
                console.warn('⚠️ Fallback configuration not working');
            }

        } catch (error) {
            console.error(`❌ Test failed for ${type}:`, error);
        }

        console.groupEnd();
    });

    console.groupEnd();
}

/**
 * Test error scenarios and fallback behavior
 */
export function testErrorScenarios(): void {
    console.group('🧪 Testing Error Scenarios');

    // Test with invalid store configuration
    console.group('Testing Invalid Store Configuration');
    try {
        const invalidConfig = {
            hp_type: 'test',
            // Missing required fields
        };

        const config = generateDefaultConfig('test', invalidConfig);
        console.log('✅ Fallback used for invalid config:', config);
    } catch (error) {
        console.error('❌ Error handling failed:', error);
    }
    console.groupEnd();

    // Test with null/undefined store configuration
    console.group('Testing Null Store Configuration');
    try {
        const config = generateDefaultConfig('test', null);
        console.log('✅ Fallback used for null config:', config);
    } catch (error) {
        console.error('❌ Error handling failed:', error);
    }
    console.groupEnd();

    // Test with empty store configuration
    console.group('Testing Empty Store Configuration');
    try {
        const config = generateDefaultConfig('test', {});
        console.log('✅ Fallback used for empty config:', config);
    } catch (error) {
        console.error('❌ Error handling failed:', error);
    }
    console.groupEnd();

    console.groupEnd();
}

/**
 * Test configuration parsing utilities
 */
export function testConfigurationParsing(): void {
    console.group('🧪 Testing Configuration Parsing');

    const testStoreConfig = KNOWN_HONEYPOT_TESTS.cowrie.storeConfig;

    try {
        // Test store configuration validation
        const validation = validateStoreConfiguration(testStoreConfig);
        console.log('✅ Store config validation:', validation);

        // Test configuration parsing
        const parsedConfig = parseStoreConfiguration(testStoreConfig);
        console.log('✅ Parsed configuration:', parsedConfig);

        // Test service generation
        const services = generateServicesFromStoreConfig(testStoreConfig);
        console.log('✅ Generated services:', services);

        // Test configuration conversion
        const dynamicConfig = convertStoreConfigToDynamicConfig(
            testStoreConfig.default_configuration,
            testStoreConfig.hp_type,
            testStoreConfig
        );
        console.log('✅ Dynamic config:', dynamicConfig);

    } catch (error) {
        console.error('❌ Parsing test failed:', error);
    }

    console.groupEnd();
}

/**
 * Run all configuration tests
 */
export function runAllConfigurationTests(): void {
    console.log('🚀 Starting Configuration System Tests');
    console.log('=====================================');

    testKnownHoneypotTypes();
    testUnknownHoneypotTypes();
    testErrorScenarios();
    testConfigurationParsing();

    console.log('✅ All tests completed');
}

/**
 * Test specific honeypot type
 */
export function testSpecificHoneypotType(type: string, storeConfig?: any): void {
    console.group(`🧪 Testing Specific Honeypot: ${type}`);

    try {
        const config = generateDefaultConfig(type, storeConfig);
        console.log('Generated config:', config);

        // Log detailed steps
        if (storeConfig) {
            const parsedConfig = parseStoreConfiguration(storeConfig);
            const services = generateServicesFromStoreConfig(storeConfig);

            logConfigurationSteps(
                type,
                storeConfig,
                parsedConfig,
                services,
                config,
                false
            );
        }

    } catch (error) {
        console.error('Test failed:', error);
    }

    console.groupEnd();
}
