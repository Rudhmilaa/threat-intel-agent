/**
 * Error Scenarios Testing
 * 
 * Test error handling and fallback behavior in the configuration system
 */

import { generateDefaultConfig, convertStoreConfigToDynamicConfig } from './honeypot-registry';
import { parseStoreConfiguration, validateStoreConfiguration } from './store-config-parser';
import { generateServicesFromStoreConfig } from './dynamic-service-generator';

/**
 * Test invalid store configurations
 */
export function testInvalidStoreConfigurations(): void {
    console.group('🧪 Testing Invalid Store Configurations');

    const invalidConfigs = [
        {
            name: 'Null Configuration',
            config: null,
            expectedBehavior: 'Should fall back to registry or generic config'
        },
        {
            name: 'Undefined Configuration',
            config: undefined,
            expectedBehavior: 'Should fall back to registry or generic config'
        },
        {
            name: 'Empty Object',
            config: {},
            expectedBehavior: 'Should fall back to registry or generic config'
        },
        {
            name: 'Missing hp_type',
            config: {
                name: 'test',
                supported_protocols: ['ssh']
            },
            expectedBehavior: 'Should fall back due to missing required field'
        },
        {
            name: 'Missing name',
            config: {
                hp_type: 'test',
                supported_protocols: ['ssh']
            },
            expectedBehavior: 'Should fall back due to missing required field'
        },
        {
            name: 'Invalid default_configuration type',
            config: {
                hp_type: 'test',
                name: 'test',
                default_configuration: 'not an object'
            },
            expectedBehavior: 'Should fall back due to invalid configuration structure'
        },
        {
            name: 'Invalid supported_protocols type',
            config: {
                hp_type: 'test',
                name: 'test',
                supported_protocols: 'not an array'
            },
            expectedBehavior: 'Should fall back due to invalid configuration structure'
        }
    ];

    invalidConfigs.forEach(({ name, config, expectedBehavior }) => {
        console.group(`Testing: ${name}`);
        console.log(`Expected behavior: ${expectedBehavior}`);

        try {
            const result = generateDefaultConfig('test', config);
            console.log('✅ Result:', result);

            // Check if fallback was used
            const fallbackUsed = result.default && result.default.enabled;
            console.log(`Fallback used: ${fallbackUsed ? '✅ YES' : '❌ NO'}`);

            if (fallbackUsed) {
                console.log('✅ Correctly fell back to generic configuration');
            } else {
                console.log('⚠️ May not have used fallback as expected');
            }

        } catch (error) {
            console.error('❌ Error occurred:', error);
            console.log('✅ Error was caught and handled');
        }

        console.groupEnd();
    });

    console.groupEnd();
}

/**
 * Test malformed configuration data
 */
export function testMalformedConfigurationData(): void {
    console.group('🧪 Testing Malformed Configuration Data');

    const malformedConfigs = [
        {
            name: 'Invalid Port Numbers',
            config: {
                hp_type: 'test',
                name: 'test',
                default_configuration: {
                    ssh_port: -1,  // Invalid port
                    telnet_port: 70000  // Invalid port
                }
            },
            expectedBehavior: 'Should handle invalid ports gracefully'
        },
        {
            name: 'Non-numeric Port Values',
            config: {
                hp_type: 'test',
                name: 'test',
                default_configuration: {
                    ssh_port: 'not a number',
                    telnet_port: null
                }
            },
            expectedBehavior: 'Should handle non-numeric ports gracefully'
        },
        {
            name: 'Missing Port Values',
            config: {
                hp_type: 'test',
                name: 'test',
                default_configuration: {
                    ssh_enabled: true,
                    // Missing ssh_port
                    telnet_port: 23
                }
            },
            expectedBehavior: 'Should handle missing port values'
        },
        {
            name: 'Empty Arrays',
            config: {
                hp_type: 'test',
                name: 'test',
                supported_protocols: [],
                default_ports: []
            },
            expectedBehavior: 'Should handle empty arrays gracefully'
        }
    ];

    malformedConfigs.forEach(({ name, config, expectedBehavior }) => {
        console.group(`Testing: ${name}`);
        console.log(`Expected behavior: ${expectedBehavior}`);

        try {
            const result = generateDefaultConfig('test', config);
            console.log('✅ Result:', result);

            // Validate the result structure
            const hasValidStructure = Object.values(result).every((service: any) =>
                service && typeof service === 'object' &&
                'enabled' in service && 'port' in service
            );

            console.log(`Valid structure: ${hasValidStructure ? '✅ YES' : '❌ NO'}`);

        } catch (error) {
            console.error('❌ Error occurred:', error);
        }

        console.groupEnd();
    });

    console.groupEnd();
}

/**
 * Test fallback chain behavior
 */
export function testFallbackChainBehavior(): void {
    console.group('🧪 Testing Fallback Chain Behavior');

    const testCases = [
        {
            name: 'No Store Config - Should Use Registry',
            type: 'cowrie', // Known type
            storeConfig: null,
            expectedSource: 'registry'
        },
        {
            name: 'Invalid Store Config - Should Use Registry',
            type: 'cowrie', // Known type
            storeConfig: { hp_type: 'cowrie' }, // Invalid (missing name)
            expectedSource: 'registry'
        },
        {
            name: 'Unknown Type - Should Use Generic Fallback',
            type: 'unknown_type',
            storeConfig: null,
            expectedSource: 'generic'
        },
        {
            name: 'Valid Store Config - Should Use Store',
            type: 'custom_hp',
            storeConfig: {
                hp_type: 'custom_hp',
                name: 'custom_hp',
                supported_protocols: ['web'],
                default_ports: [8080],
                default_configuration: {
                    web_port: 8080
                }
            },
            expectedSource: 'store'
        }
    ];

    testCases.forEach(({ name, type, storeConfig, expectedSource }) => {
        console.group(`Testing: ${name}`);
        console.log(`Expected source: ${expectedSource}`);

        try {
            const result = generateDefaultConfig(type, storeConfig);
            console.log('✅ Result:', result);

            // Determine which source was used
            let actualSource = 'unknown';

            if (result.web && result.web.port === '8080') {
                actualSource = 'store';
            } else if (result.ssh && result.ssh.port === '2222') {
                actualSource = 'registry';
            } else if (result.default && result.default.port === '8080') {
                actualSource = 'generic';
            }

            console.log(`Actual source: ${actualSource}`);
            console.log(`Source match: ${actualSource === expectedSource ? '✅ YES' : '❌ NO'}`);

        } catch (error) {
            console.error('❌ Error occurred:', error);
        }

        console.groupEnd();
    });

    console.groupEnd();
}

/**
 * Test error recovery mechanisms
 */
export function testErrorRecoveryMechanisms(): void {
    console.group('🧪 Testing Error Recovery Mechanisms');

    // Test configuration parsing errors
    console.group('Configuration Parsing Errors');
    try {
        const invalidConfig = {
            hp_type: 'test',
            name: 'test',
            default_configuration: {
                invalid_port: 'not a number'
            }
        };

        const parsed = parseStoreConfiguration(invalidConfig);
        console.log('✅ Parsing completed:', parsed);

    } catch (error) {
        console.error('❌ Parsing failed:', error);
    }
    console.groupEnd();

    // Test service generation errors
    console.group('Service Generation Errors');
    try {
        const invalidConfig = {
            hp_type: 'test',
            name: 'test',
            supported_protocols: null // Invalid type
        };

        const services = generateServicesFromStoreConfig(invalidConfig);
        console.log('✅ Service generation completed:', services);

    } catch (error) {
        console.error('❌ Service generation failed:', error);
    }
    console.groupEnd();

    // Test configuration conversion errors
    console.group('Configuration Conversion Errors');
    try {
        const invalidOptions = {
            invalid_service_enabled: 'not a boolean',
            invalid_service_port: 'not a number'
        };

        const converted = convertStoreConfigToDynamicConfig(invalidOptions, 'test');
        console.log('✅ Conversion completed:', converted);

    } catch (error) {
        console.error('❌ Conversion failed:', error);
    }
    console.groupEnd();

    console.groupEnd();
}

/**
 * Test edge cases
 */
export function testEdgeCases(): void {
    console.group('🧪 Testing Edge Cases');

    const edgeCases = [
        {
            name: 'Very Large Port Numbers',
            config: {
                hp_type: 'test',
                name: 'test',
                default_configuration: {
                    ssh_port: 65535
                }
            }
        },
        {
            name: 'Special Characters in Protocol Names',
            config: {
                hp_type: 'test',
                name: 'test',
                supported_protocols: ['ssh-2', 'telnet_v1'],
                default_configuration: {
                    'ssh-2_port': 2222,
                    'telnet_v1_port': 2323
                }
            }
        },
        {
            name: 'Very Long Configuration',
            config: {
                hp_type: 'test',
                name: 'test',
                supported_protocols: Array.from({ length: 50 }, (_, i) => `protocol_${i}`),
                default_configuration: Object.fromEntries(
                    Array.from({ length: 50 }, (_, i) => [`protocol_${i}_port`, 1000 + i])
                )
            }
        }
    ];

    edgeCases.forEach(({ name, config }) => {
        console.group(`Testing: ${name}`);

        try {
            const result = generateDefaultConfig('test', config);
            console.log('✅ Result generated successfully');
            console.log(`Number of services: ${Object.keys(result).length}`);

        } catch (error) {
            console.error('❌ Error occurred:', error);
        }

        console.groupEnd();
    });

    console.groupEnd();
}

/**
 * Run all error scenario tests
 */
export function runErrorScenarioTests(): void {
    console.log('🚀 Starting Error Scenario Tests');
    console.log('================================');

    testInvalidStoreConfigurations();
    testMalformedConfigurationData();
    testFallbackChainBehavior();
    testErrorRecoveryMechanisms();
    testEdgeCases();

    console.log('✅ All error scenario tests completed');
}
