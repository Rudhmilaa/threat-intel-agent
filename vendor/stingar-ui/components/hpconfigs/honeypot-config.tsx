import { Accordion } from "@/components/ui/accordion";
import {
  HoneypotConfigType,
  HoneypotType,
  ServiceConfig,
} from "@/models/honeypots";
import { ServiceConfigItem } from "./service-config-item";
import { generateServicesFromStoreConfig, ServiceConfig as DynamicServiceConfig } from "@/lib/dynamic-service-generator";

type HoneypotConfigProps = {
  type: HoneypotType;
  config: HoneypotConfigType;
  onChange: (config: HoneypotConfigType) => void;
  storeConfig?: any; // Add optional store configuration
};

export function HoneypotConfig({ type, config, onChange, storeConfig }: HoneypotConfigProps) {
  const handleServiceChange = (
    serviceName: string,
    serviceConfig: ServiceConfig
  ) => {
    onChange({
      ...config,
      [serviceName]: serviceConfig,
    } as HoneypotConfigType);
  };

    // Generate dynamic services from store config if available
  const dynamicServices: DynamicServiceConfig[] = storeConfig ? generateServicesFromStoreConfig(storeConfig) : [];
  
  // Merge dynamic services with existing config
  // Use a more flexible type for merged config to handle dynamic services
  const mergedConfig: Record<string, ServiceConfig> = { ...config as Record<string, ServiceConfig> };
  if (dynamicServices.length > 0) {
    dynamicServices.forEach(service => {
      if (!mergedConfig[service.name]) {
        mergedConfig[service.name] = {
          enabled: service.enabled,
          port: service.port
        };
      }
    });
  }

  const enabledServices = Object.entries(mergedConfig)
    .filter(([_, cfg]) => cfg.enabled)
    .map(([name]) => name);

  return (
    <Accordion
      type="multiple"
      value={enabledServices}
      onValueChange={(values) => {
        const newConfig = { ...mergedConfig };
        Object.keys(mergedConfig).forEach((service) => {
          newConfig[service] = {
            ...mergedConfig[service],
            enabled: values.includes(service),
          };
        });
        onChange(newConfig as HoneypotConfigType);
      }}
    >
      {Object.entries(mergedConfig).map(([serviceName, serviceConfig]) => (
        <ServiceConfigItem
          key={serviceName}
          serviceName={serviceName}
          config={serviceConfig}
          onChange={(cfg) => handleServiceChange(serviceName, cfg)}
        />
      ))}
    </Accordion>
  );
}
