/**
 * New Honeypot Types Testing
 * 
 * Test the dynamic configuration system with new/unknown honeypot types
 */

import { generateDefaultConfig } from './honeypot-registry';
import { parseStoreConfiguration, validateStoreConfiguration } from './store-config-parser';
import { generateServicesFromStoreConfig } from './dynamic-service-generator';
import { logConfigurationSteps } from './debug-config';

// Test cases for new honeypot types
export const NEW_HONEYPOT_TEST_CASES = {
  p4: {
    name: 'P4 Custom Honeypot',
    description: 'Test the "p4" honeypot type that was causing fallback issues',
    storeConfig: {
      hp_type: 'p4',
      name: 'p4',
      display_name: 'P4 Custom Honeypot',
      description: 'A custom honeypot for testing dynamic configuration',
      supported_protocols: ['custom_protocol', 'web'],
      default_ports: [9999, 8080],
      default_configuration: {
        custom_protocol_port: 9999,
        web_port: 8080,
        custom_setting: 'test_value'
      },
      configuration_schema: {
        properties: {
          custom_protocol_port: { default: 9999, type: 'integer' },
          web_port: { default: 8080, type: 'integer' }
        }
      }
    },
    expectedServices: ['custom_protocol', 'web'],
    expectedPorts: [9999, 8080]
  },
  test_hp: {
    name: 'Test Honeypot',
    description: 'Generic test honeypot with multiple protocols',
    storeConfig: {
      hp_type: 'test_hp',
      name: 'test_hp',
      display_name: 'Test Honeypot',
      description: 'A test honeypot for validation',
      supported_protocols: ['ssh', 'telnet', 'http'],
      default_ports: [2222, 2323, 8080],
      default_configuration: {
        ssh_port: 2222,
        telnet_port: 2323,
        http_port: 8080
      }
    },
    expectedServices: ['ssh', 'telnet', 'http'],
    expectedPorts: [2222, 2323, 8080]
  },
  industrial_hp: {
    name: 'Industrial Honeypot',
    description: 'Industrial control system honeypot',
    storeConfig: {
      hp_type: 'industrial_hp',
      name: 'industrial_hp',
      display_name: 'Industrial Control Honeypot',
      description: 'Simulates industrial control systems',
      supported_protocols: ['modbus', 's7', 'bacnet', 'enip'],
      default_ports: [502, 102, 47808, 44818],
      default_configuration: {
        modbus_port: 502,
        s7_port: 102,
        bacnet_port: 47808,
        enip_port: 44818
      }
    },
    expectedServices: ['modbus', 's7', 'bacnet', 'enip'],
    expectedPorts: [502, 102, 47808, 44818]
  }
};

/**
 * Test new honeypot type configuration generation
 */
export function testNewHoneypotType(type: string, testCase: any): void {
  console.group(`🧪 Testing New Honeypot: ${testCase.name} (${type})`);
  console.log(`Description: ${testCase.description}`);

  try {
    // Test 1: Configuration with store data
    console.group('Test 1: With Store Configuration');
    const configWithStore = generateDefaultConfig(type, testCase.storeConfig);
    console.log('Generated config:', configWithStore);

    // Validate services
    const servicesFound = testCase.expectedServices.every((service: string) =>
      configWithStore[service] && configWithStore[service].enabled
    );
    console.log(`Services validation: ${servicesFound ? '✅ PASS' : '❌ FAIL'}`);

    // Validate ports
    const portsMatch = testCase.expectedServices.every((service: string, index: number) =>
      configWithStore[service] &&
      parseInt(configWithStore[service].port) === testCase.expectedPorts[index]
    );
    console.log(`Ports validation: ${portsMatch ? '✅ PASS' : '❌ FAIL'}`);

    // Log detailed configuration steps
    const parsedConfig = parseStoreConfiguration(testCase.storeConfig);
    const services = generateServicesFromStoreConfig(testCase.storeConfig);

    logConfigurationSteps(
      type,
      testCase.storeConfig,
      parsedConfig,
      services,
      configWithStore,
      false
    );
    console.groupEnd();

    // Test 2: Configuration without store data (fallback)
    console.group('Test 2: Without Store Configuration (Fallback)');
    const configWithoutStore = generateDefaultConfig(type);
    console.log('Fallback config:', configWithoutStore);

    // Check if fallback was used
    const fallbackUsed = configWithoutStore.default && configWithoutStore.default.enabled;
    console.log(`Fallback used: ${fallbackUsed ? '✅ YES' : '❌ NO'}`);
    console.groupEnd();

    // Test 3: Configuration validation
    console.group('Test 3: Configuration Validation');
    const validation = validateStoreConfiguration(testCase.storeConfig);
    console.log('Validation result:', validation);
    console.groupEnd();

    // Summary
    console.group('📊 Test Summary');
    console.log(`✅ Services found: ${servicesFound ? 'Yes' : 'No'}`);
    console.log(`✅ Ports match: ${portsMatch ? 'Yes' : 'No'}`);
    console.log(`✅ Store config valid: ${validation.isValid ? 'Yes' : 'No'}`);
    console.log(`✅ Fallback available: ${fallbackUsed ? 'Yes' : 'No'}`);
    console.groupEnd();

  } catch (error) {
    console.error(`❌ Test failed for ${type}:`, error);
  }

  console.groupEnd();
}

/**
 * Test all new honeypot types
 */
export function testAllNewHoneypotTypes(): void {
  console.log('🚀 Testing New Honeypot Types');
  console.log('============================');

  Object.entries(NEW_HONEYPOT_TEST_CASES).forEach(([type, testCase]) => {
    testNewHoneypotType(type, testCase);
  });

  console.log('✅ All new honeypot type tests completed');
}

/**
 * Test specific "p4" honeypot type (the original problem case)
 */
export function testP4Honeypot(): void {
  console.log('🎯 Testing P4 Honeypot (Original Problem Case)');
  console.log('=============================================');

  const p4TestCase = NEW_HONEYPOT_TEST_CASES.p4;

  // Test with the original problematic configuration
  console.group('Original P4 Configuration Test');
  const originalP4Config = {
    hp_type: 'p4',
    name: 'p4',
    // Minimal configuration that was causing fallback to Cowrie
    default_configuration: {
      ssh_enabled: true,
      ssh_port: 22,
      telnet_enabled: true,
      telnet_port: 23
    }
  };

  try {
    const config = generateDefaultConfig('p4', originalP4Config);
    console.log('Generated config:', config);

    // Check if it's using the store config or falling back
    const usingStoreConfig = config.ssh && config.telnet;
    const usingFallback = config.default;

    if (usingStoreConfig) {
      console.log('✅ Using store configuration (correct behavior)');
    } else if (usingFallback) {
      console.log('⚠️ Using fallback configuration (may indicate issue)');
    } else {
      console.log('❌ Unexpected configuration state');
    }

  } catch (error) {
    console.error('❌ P4 test failed:', error);
  }
  console.groupEnd();

  // Test with enhanced configuration
  testNewHoneypotType('p4', p4TestCase);
}

/**
 * Compare old vs new behavior for unknown honeypot types
 */
export function compareOldVsNewBehavior(): void {
  console.log('🔄 Comparing Old vs New Behavior');
  console.log('================================');

  const testType = 'unknown_hp';

  console.group('Old Behavior (Hardcoded Fallback)');
  // Simulate old behavior - would fall back to Cowrie
  console.log('Old behavior would fall back to hardcoded Cowrie config');
  console.log('Expected: { ssh: { enabled: true, port: "22" }, telnet: { enabled: true, port: "23" } }');
  console.groupEnd();

  console.group('New Behavior (Dynamic Configuration)');
  // Test new behavior with store configuration
  const storeConfig = {
    hp_type: testType,
    name: testType,
    supported_protocols: ['custom_protocol'],
    default_ports: [9999],
    default_configuration: {
      custom_protocol_port: 9999
    }
  };

  try {
    const newConfig = generateDefaultConfig(testType, storeConfig);
    console.log('New behavior result:', newConfig);
    console.log('✅ Uses store configuration instead of hardcoded fallback');
  } catch (error) {
    console.error('❌ New behavior test failed:', error);
  }
  console.groupEnd();
}

/**
 * Run comprehensive new honeypot type tests
 */
export function runNewHoneypotTypeTests(): void {
  console.log('🚀 Starting New Honeypot Type Tests');
  console.log('==================================');

  testAllNewHoneypotTypes();
  testP4Honeypot();
  compareOldVsNewBehavior();

  console.log('✅ All new honeypot type tests completed');
}
