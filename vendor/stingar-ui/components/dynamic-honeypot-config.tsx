/**
 * Dynamic Honeypot Configuration Component
 * 
 * This component automatically adapts to any honeypot type and provides
 * a configuration interface based on the honeypot's service definitions.
 */

import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { Label } from "./ui/label";
import { Checkbox } from "./ui/checkbox";
import { Input } from "./ui/input";
import { Separator } from "./ui/separator";
import { Badge } from "./ui/badge";
import {
    getHoneypotTypeDefinition,
    type DynamicHoneypotConfig,
    type HoneypotTypeDefinition
} from "@/lib/honeypot-registry";

interface DynamicHoneypotConfigProps {
    type: string;
    config: DynamicHoneypotConfig;
    onChange: (config: DynamicHoneypotConfig) => void;
    disabled?: boolean;
}

export function DynamicHoneypotConfig({
    type,
    config,
    onChange,
    disabled = false
}: DynamicHoneypotConfigProps) {
    const definition = getHoneypotTypeDefinition(type);

    const handleServiceToggle = (serviceName: string, enabled: boolean) => {
        const newConfig = { ...config };
        if (newConfig[serviceName]) {
            newConfig[serviceName].enabled = enabled;
        } else {
            newConfig[serviceName] = { enabled, port: "0" };
        }
        onChange(newConfig);
    };

    const handlePortChange = (serviceName: string, port: string) => {
        const newConfig = { ...config };
        if (newConfig[serviceName]) {
            newConfig[serviceName].port = port;
        } else {
            newConfig[serviceName] = { enabled: true, port };
        }
        onChange(newConfig);
    };

    const getCategoryColor = (category: string) => {
        switch (category) {
            case 'network': return 'bg-blue-100 text-blue-800 border-blue-300';
            case 'web': return 'bg-green-100 text-green-800 border-green-300';
            case 'industrial': return 'bg-orange-100 text-orange-800 border-orange-300';
            case 'malware': return 'bg-red-100 text-red-800 border-red-300';
            case 'custom': return 'bg-purple-100 text-purple-800 border-purple-300';
            default: return 'bg-gray-100 text-gray-800 border-gray-300';
        }
    };

    if (!definition) {
        return (
            <Card className="w-full">
                <CardHeader>
                    <CardTitle className="text-lg text-gray-600">Unknown Honeypot Type</CardTitle>
                    <CardDescription>
                        No configuration template found for honeypot type: <code className="bg-gray-100 px-1 rounded">{type}</code>
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    <div className="text-sm text-gray-600">
                        This honeypot type is not yet registered in the system.
                        You can still configure it manually using the legacy interface.
                    </div>
                </CardContent>
            </Card>
        );
    }

    return (
        <Card className="w-full">
            <CardHeader>
                <div className="flex items-center justify-between">
                    <div>
                        <CardTitle className="text-lg">{definition.name}</CardTitle>
                        <CardDescription className="mt-1">
                            {definition.description}
                        </CardDescription>
                    </div>
                    <Badge className={getCategoryColor(definition.category)}>
                        {definition.category}
                    </Badge>
                </div>
            </CardHeader>
            <CardContent className="space-y-6">
                <div className="grid gap-4">
                    {definition.services.map((service) => {
                        const serviceConfig = config[service.name] || { enabled: false, port: service.defaultPort.toString() };

                        return (
                            <div key={service.name} className="space-y-3">
                                <div className="flex items-center justify-between">
                                    <div className="space-y-1">
                                        <Label className="text-sm font-medium capitalize">
                                            {service.name} Service
                                        </Label>
                                        {service.description && (
                                            <p className="text-xs text-gray-600">{service.description}</p>
                                        )}
                                    </div>
                                    <Checkbox
                                        checked={serviceConfig.enabled}
                                        onCheckedChange={(enabled: boolean) => handleServiceToggle(service.name, enabled)}
                                        disabled={disabled}
                                    />
                                </div>

                                {serviceConfig.enabled && (
                                    <div className="space-y-2">
                                        <Label htmlFor={`port-${service.name}`} className="text-xs">
                                            Port Number
                                        </Label>
                                        <Input
                                            id={`port-${service.name}`}
                                            type="number"
                                            value={serviceConfig.port}
                                            onChange={(e) => handlePortChange(service.name, e.target.value)}
                                            placeholder={service.defaultPort.toString()}
                                            disabled={disabled}
                                            className="w-32"
                                        />
                                        <p className="text-xs text-gray-600">
                                            Default port: {service.defaultPort}
                                        </p>
                                    </div>
                                )}

                                <Separator />
                            </div>
                        );
                    })}
                </div>

                {Object.keys(config).length === 0 && (
                    <div className="text-center py-4 text-gray-600">
                        <p className="text-sm">No services configured</p>
                        <p className="text-xs">Enable services above to configure this honeypot</p>
                    </div>
                )}

                {Object.keys(config).length > 0 && (
                    <div className="mt-4 p-3 bg-gray-50 rounded-lg">
                        <h4 className="text-sm font-medium mb-2">Configuration Summary</h4>
                        <div className="space-y-1">
                            {Object.entries(config).map(([serviceName, serviceConfig]) => (
                                <div key={serviceName} className="flex justify-between text-xs">
                                    <span className="capitalize">{serviceName}:</span>
                                    <span className={serviceConfig.enabled ? "text-green-600" : "text-gray-400"}>
                                        {serviceConfig.enabled ? `Port ${serviceConfig.port}` : "Disabled"}
                                    </span>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}

/**
 * Hook for managing dynamic honeypot configuration
 */
export function useDynamicHoneypotConfig(type: string) {
    const [config, setConfig] = React.useState<DynamicHoneypotConfig>(() => {
        const definition = getHoneypotTypeDefinition(type);
        if (!definition) return {};

        const defaultConfig: DynamicHoneypotConfig = {};
        definition.services.forEach(service => {
            defaultConfig[service.name] = {
                enabled: definition.defaultEnabled,
                port: service.defaultPort.toString()
            };
        });
        return defaultConfig;
    });

    const updateConfig = React.useCallback((newConfig: DynamicHoneypotConfig) => {
        setConfig(newConfig);
    }, []);

    const resetConfig = React.useCallback(() => {
        const definition = getHoneypotTypeDefinition(type);
        if (!definition) return;

        const defaultConfig: DynamicHoneypotConfig = {};
        definition.services.forEach(service => {
            defaultConfig[service.name] = {
                enabled: definition.defaultEnabled,
                port: service.defaultPort.toString()
            };
        });
        setConfig(defaultConfig);
    }, [type]);

    return {
        config,
        updateConfig,
        resetConfig
    };
}
