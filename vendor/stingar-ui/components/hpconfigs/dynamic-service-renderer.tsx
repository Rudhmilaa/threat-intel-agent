/**
 * Dynamic Service Renderer Component
 * 
 * Renders service configurations dynamically based on HP App Store metadata
 */

import React from 'react';
import { ServiceConfig as DynamicServiceConfig } from '@/lib/dynamic-service-generator';
import { ServiceConfig } from '@/models/honeypots';
import { ServiceConfigItem } from './service-config-item';

interface DynamicServiceRendererProps {
  services: DynamicServiceConfig[];
  config: Record<string, { enabled: boolean; port: string }>;
  onChange: (config: Record<string, { enabled: boolean; port: string }>) => void;
  showDescriptions?: boolean;
}

export function DynamicServiceRenderer({
  services,
  config,
  onChange,
  showDescriptions = true
}: DynamicServiceRendererProps) {

  const handleServiceChange = (serviceName: string, serviceConfig: { enabled: boolean; port: string }) => {
    const newConfig = {
      ...config,
      [serviceName]: serviceConfig
    };
    onChange(newConfig);
  };

  const handleBulkToggle = (enabled: boolean) => {
    const newConfig = { ...config };
    services.forEach(service => {
      newConfig[service.name] = {
        ...newConfig[service.name],
        enabled
      };
    });
    onChange(newConfig);
  };

  const enabledCount = services.filter(service => config[service.name]?.enabled).length;

  return (
    <div className="space-y-4">
      {/* Bulk Actions */}
      <div className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
        <div className="text-sm text-gray-600">
          {enabledCount} of {services.length} services enabled
        </div>
        <div className="space-x-2">
          <button
            onClick={() => handleBulkToggle(true)}
            className="px-3 py-1 text-sm bg-green-100 text-green-700 rounded hover:bg-green-200"
          >
            Enable All
          </button>
          <button
            onClick={() => handleBulkToggle(false)}
            className="px-3 py-1 text-sm bg-red-100 text-red-700 rounded hover:bg-red-200"
          >
            Disable All
          </button>
        </div>
      </div>

      {/* Service List */}
      <div className="space-y-2">
        {services.map(service => {
          const currentConfig = config[service.name] || {
            enabled: service.enabled,
            port: service.port
          };

          return (
            <div
              key={service.name}
              className={`p-4 border rounded-lg transition-colors ${currentConfig.enabled
                ? 'border-blue-200 bg-blue-50'
                : 'border-gray-200 bg-gray-50'
                }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-2">
                    <h3 className="font-medium text-gray-900 capitalize">
                      {service.name}
                    </h3>
                    {showDescriptions && service.description && (
                      <span className="text-sm text-gray-600">
                        ({service.description})
                      </span>
                    )}
                  </div>
                  {service.defaultPort && (
                    <p className="text-xs text-gray-600 mt-1">
                      Default port: {service.defaultPort}
                    </p>
                  )}
                </div>

                <ServiceConfigItem
                  serviceName={service.name}
                  config={currentConfig}
                  onChange={(newConfig) => handleServiceChange(service.name, newConfig)}
                />
              </div>
            </div>
          );
        })}
      </div>

      {/* Empty State */}
      {services.length === 0 && (
        <div className="text-center py-8 text-gray-600">
          <p>No services configured for this honeypot type.</p>
          <p className="text-sm mt-1">
            Check the HP App Store configuration for available services.
          </p>
        </div>
      )}
    </div>
  );
}

/**
 * Compact version for use in smaller spaces
 */
export function CompactDynamicServiceRenderer({
  services,
  config,
  onChange
}: Omit<DynamicServiceRendererProps, 'showDescriptions'>) {

  const handleServiceChange = (serviceName: string, serviceConfig: { enabled: boolean; port: string }) => {
    const newConfig = {
      ...config,
      [serviceName]: serviceConfig
    };
    onChange(newConfig);
  };

  return (
    <div className="space-y-2">
      {services.map(service => {
        const currentConfig = config[service.name] || {
          enabled: service.enabled,
          port: service.port
        };

        return (
          <div
            key={service.name}
            className={`p-3 border rounded transition-colors ${currentConfig.enabled
              ? 'border-blue-200 bg-blue-50'
              : 'border-gray-200 bg-gray-50'
              }`}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="font-medium text-sm capitalize">
                  {service.name}
                </span>
                <span className="text-xs text-gray-600">
                  (port {currentConfig.port})
                </span>
              </div>

              <ServiceConfigItem
                serviceName={service.name}
                config={currentConfig}
                onChange={(newConfig) => handleServiceChange(service.name, newConfig)}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}
