"use client";

import { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
} from "@/components/ui/card";
import { HostCombobox } from "../host-combobox";
import { Host } from "@/models/hosts";
import { toast } from "sonner";
import { useHosts, useKeys } from "@/components/hooks/hooks";
import { useConfigs } from "@/lib/hooks/use-configs";
import {
  createDeployment,
  createComposeNoSave,
  createEnvNoSave,
  getConfig,
} from "@/lib/actions";

import { Label } from "../ui/label";
import {
  DEFAULT_CONFIGS,
  getHoneypotConfig,
  HoneypotConfigType,
  HoneypotType,
} from "@/models/honeypots";
import { HoneypotConfig } from "../hpconfigs/honeypot-config";
import {
  convertStoreConfigToDynamicConfig,
  generateDefaultConfig,
  getHoneypotTypeDefinition,
  getHoneypotDescription,
  DynamicHoneypotConfig
} from "@/lib/honeypot-registry";
import { Button } from "@mui/material";
import { Icon } from "../icon";

export type DeployDialogProps = {
  type: HoneypotType;
  title: string;
  configId?: number;
  isStoreConfig?: boolean;
};

export function DeployDialog({ type, title, configId, isStoreConfig = false }: DeployDialogProps) {
  const { hosts } = useHosts();
  const { keys } = useKeys();
  const [host, setHost] = useState<Omit<Host, "authkeyName">>();
  const [hpConfig, setHpConfig] = useState<HoneypotConfigType>(() => {
    // Don't initialize with default config immediately - let loadStoreConfig handle it
    return {} as any;
  });
  const [activeTab, setActiveTab] = useState<"host" | "hp" | "preview">("host");
  const [open, setOpen] = useState(false);
  const [isLoadingConfig, setIsLoadingConfig] = useState(false);

  // Safety check for type parameter - moved after all hooks
  if (!type) {
    console.error("DeployDialog: type parameter is undefined or null");
    return (
      <Button variant="contained" color="primary" disabled>
        Deploy (Invalid Type)
      </Button>
    );
  }

  // Load store configuration when needed
  const loadStoreConfig = async () => {
    if (isStoreConfig && configId) {
      try {
        setIsLoadingConfig(true);
        const storeConfig = await getConfig(configId.toString());

        // Safety check for hp_options (handle both snake_case and camelCase)
        const hpOptions = storeConfig.hp_options || (storeConfig as any).hpOptions;
        if (!hpOptions) {
          console.warn("Store config has no hp_options, using default");
          setHpConfig(generateDefaultConfig(type) as any);
          return;
        }

        // Parse hp_options if it's a JSON string
        let parsedHpOptions = hpOptions;
        if (typeof hpOptions === 'string') {
          try {
            parsedHpOptions = JSON.parse(hpOptions);
          } catch (parseError) {
            console.error("Failed to parse hp_options JSON:", parseError);
            setHpConfig(generateDefaultConfig(type) as any);
            return;
          }
        }

        // Convert store configuration format using dynamic system with full store config
        const convertedConfig = convertStoreConfigToDynamicConfig(parsedHpOptions, type, storeConfig);
        setHpConfig(convertedConfig as any);
      } catch (error) {
        console.error("Failed to load store configuration:", error);
        toast.error("Failed to load configuration. Using default settings.");

        // Enhanced error recovery: try multiple fallback strategies
        try {
          const fallbackConfig = generateDefaultConfig(type);
          setHpConfig(fallbackConfig as any);
          toast.info("Using fallback configuration. Some features may be limited.");
        } catch (fallbackError) {
          console.error("Fallback configuration also failed:", fallbackError);
          toast.error("Configuration loading failed completely. Please try again.");
          setHpConfig(getHoneypotConfig(type));
        }
      } finally {
        setIsLoadingConfig(false);
      }
    } else {
      setHpConfig(generateDefaultConfig(type) as any);
    }
  };

  // Retry mechanism for failed configuration loads
  const retryLoadConfig = async (retryCount = 0, maxRetries = 3) => {
    if (retryCount >= maxRetries) {
      console.error(`Failed to load configuration after ${maxRetries} attempts`);
      toast.error("Configuration loading failed after multiple attempts. Using safe defaults.");
      setHpConfig(getHoneypotConfig(type));
      return;
    }

    try {
      await loadStoreConfig();
    } catch (error) {
      console.error(`Configuration load attempt ${retryCount + 1} failed:`, error);
      toast.warning(`Configuration load failed, retrying... (${retryCount + 1}/${maxRetries})`);

      // Wait before retrying
      setTimeout(() => {
        retryLoadConfig(retryCount + 1, maxRetries);
      }, 1000 * (retryCount + 1)); // Exponential backoff
    }
  };

  // Enhanced configuration loading with store metadata
  const loadStoreConfigWithMetadata = async (storeConfig: any) => {
    try {

      // Import store config parser
      const { parseStoreConfiguration, validateStoreConfiguration } = await import('../../lib/store-config-parser');

      // Validate store configuration
      const validation = validateStoreConfiguration(storeConfig);
      if (!validation.isValid) {
        console.warn("Invalid store configuration:", validation.errors);
        return generateDefaultConfig(type);
      }

      // Parse store configuration
      const parsedConfig = parseStoreConfiguration(storeConfig);

      // Generate dynamic configuration
      const dynamicConfig = generateDefaultConfig(type, storeConfig);

      return dynamicConfig;
    } catch (error) {
      console.error("Error loading store config with metadata:", error);
      return generateDefaultConfig(type);
    }
  };

  const handleDialogOpenChange = async (isOpen: boolean) => {
    if (isOpen) {
      await loadStoreConfig();
    } else {
      setActiveTab("host");
      setHost(undefined);
      setHpConfig(getHoneypotConfig(type));
    }
    setOpen(isOpen);
  };

  const downloadFile = (file: Blob, filename: string) => {
    // Create a URL for the blob
    const url = window.URL.createObjectURL(file);

    // Create a temporary anchor element
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;

    // Append to body, click, and remove
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    // Clean up the URL
    window.URL.revokeObjectURL(url);
  };

  const handleDeployNoSave = () => {
    // Safety check for hpConfig
    if (!hpConfig || typeof hpConfig !== 'object' || Object.keys(hpConfig).length === 0) {
      console.error("hpConfig is invalid in handleDeployNoSave:", hpConfig);
      toast.error("Configuration not loaded. Please try again.");
      return;
    }


    // Safety check for type
    if (!type) {
      console.error("type is undefined in handleDeployNoSave");
      toast.error("Honeypot type not specified. Please try again.");
      return;
    }

    try {
      const deployParams = {
        address: host?.address,
        sshPort: host?.sshPort,
        username: host?.username,
        authkeyId: host?.authkeyId,
        hp_type: type,
        hp_options: Object.entries(hpConfig).reduce(
          (acc, [service, config]) => {
            if (config && typeof config === 'object' && 'enabled' in config && 'port' in config) {
              return {
                ...acc,
                [`${service}_enabled`]: config.enabled,
                [`${service}_port`]: parseInt(config.port),
              };
            }
            return acc;
          },
          {}
        ),
        // Add config ID for store configurations so backend can load docker_image from config
        ...(isStoreConfig && configId && { config_id: configId }),
      };


      createComposeNoSave(deployParams)
        .then((compose) => {
          downloadFile(compose, "docker-compose.yml");
        })
        .catch((err) => {
          console.error(err);
          toast.error("Failed to download compose file.");
        });

      createEnvNoSave(deployParams)
        .then((env) => {
          downloadFile(env, "stingar-hp.env");
        })
        .catch((err) => {
          console.error(err);
          toast.error("Failed to download env file.");
        });
      handleDialogOpenChange(false);
    } catch (error) {
      console.error("Error in handleDeployNoSave:", error);
      toast.error("Failed to prepare deployment parameters.");
    }
  };

  const handleDeploy = async () => {
    // Safety check for hpConfig
    if (!hpConfig || typeof hpConfig !== 'object' || Object.keys(hpConfig).length === 0) {
      console.error("hpConfig is invalid in handleDeploy:", hpConfig);
      toast.error("Configuration not loaded. Please try again.");
      return;
    }


    // Safety check for type
    if (!type || type.trim() === '') {
      console.error("type is undefined or empty in handleDeploy");
      toast.error("Honeypot type not specified. Please try again.");
      return;
    }

    try {
      // Build hp_options from hpConfig
      const hpOptions = Object.entries(hpConfig).reduce(
        (acc, [service, config]) => {
          if (config && typeof config === 'object' && 'enabled' in config && 'port' in config) {
            return {
              ...acc,
              [`${service}_enabled`]: config.enabled,
              [`${service}_port`]: parseInt(config.port),
            };
          }
          return acc;
        },
        {}
      );

      // Validate hp_options is not empty
      if (Object.keys(hpOptions).length === 0) {
        console.error("No valid service configurations found in hpConfig:", hpConfig);
        toast.error("No valid service configurations found. Please check your configuration.");
        return;
      }

      // Enhanced validation for store configuration
      if (isStoreConfig && configId) {
        try {
          // Import validation functions
          const { validateStoreConfiguration } = await import('../../lib/store-config-parser');

          // Get the store configuration for validation
          const storeConfig = await getConfig(configId.toString());

          // Validate store configuration
          const validation = validateStoreConfiguration(storeConfig);
          if (!validation.isValid) {
            console.warn("Store configuration validation failed:", validation.errors);
            toast.warning("Configuration has validation issues, but proceeding with deployment");
          }
        } catch (error) {
          console.error("Error validating store configuration:", error);
          // Continue with deployment even if validation fails
        }
      }

      const deployParams = {
        address: host?.address,
        sshPort: host?.sshPort,
        username: host?.username,
        authkeyId: host?.authkeyId,
        hp_type: type,
        hp_options: hpOptions,
        // Add config ID for store configurations
        ...(isStoreConfig && configId && { config_id: configId }),
      };


      createDeployment(deployParams)
        .then((host) => {
          toast.success(
            "Deployment successfully started for host: " + host.address
          );
        })
        .catch((err) => {
          console.error("Deployment error:", err);
          toast.error("Failed to initialize deployment: " + (err.message || "Unknown error"));
        });
      handleDialogOpenChange(false);
    } catch (error: any) {
      console.error("Error in handleDeploy:", error);
      toast.error("Failed to prepare deployment parameters: " + (error.message || "Unknown error"));
    }
  };

  return (
    <>
      <Button
        onClick={async () => {
          setOpen(true);

          // Always load configuration - either store config or default config
          await loadStoreConfig();
        }}
        endIcon={<Icon className="" iconId="deploy-hp" size="5" />}
      >
        Deploy Honeypot
      </Button>
      <Dialog
        open={open}
        onOpenChange={(newOpen) => {
          handleDialogOpenChange(newOpen);
        }}
      >
        <DialogContent className="w-fit max-h-[90vh] ">
          <DialogHeader>
            <DialogTitle>
              Deploy Honeypot
              {isLoadingConfig && <span className="text-sm text-gray-600 ml-2">(Loading configuration...)</span>}
            </DialogTitle>
            <DialogDescription>
              Configure & deploy {title} honeypot.
            </DialogDescription>
          </DialogHeader>
          <div>
            <Tabs value={activeTab} className="w-[400px]">
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="host" onClick={() => setActiveTab("host")}>
                  Host Selection
                </TabsTrigger>
                <TabsTrigger
                  disabled={!host || isLoadingConfig}
                  value="hp"
                  onClick={() => setActiveTab("hp")}
                >
                  HP Configuration
                </TabsTrigger>
                <TabsTrigger
                  disabled={!host || isLoadingConfig}
                  value="preview"
                  onClick={() => setActiveTab("preview")}
                >
                  Preview
                </TabsTrigger>
              </TabsList>
              <TabsContent value="host">
                <Card>
                  <CardHeader>
                    <CardDescription>
                      Select host for the {title} honeypot. Hosts must be
                      configured before deploying.
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex flex-col gap-4 h-1/3">
                      <HostCombobox
                        className="flex-1 w-full"
                        initialHost={host?.address}
                        onValueChange={(value) => {
                          const val = hosts?.find(
                            (host) => host.address === value
                          );
                          setHost(val);
                        }}
                      />
                      <div className="grid grid-cols-[auto,1fr] text-left gap-5 m-2">
                        <Label className="font-bold">Hostname/IP:</Label>
                        <Label className="truncate">{host?.address}</Label>
                        <Label className="font-bold">SSH Port:</Label>
                        <Label className="truncate">{host?.sshPort}</Label>
                        <Label className="font-bold">Username:</Label>
                        <Label className="truncate">{host?.username}</Label>
                        <Label className="font-bold">Authentication Key:</Label>
                        <Label className="truncate">
                          {
                            keys?.find((val) => val.id === host?.authkeyId)
                              ?.name
                          }
                        </Label>
                      </div>
                    </div>
                  </CardContent>
                  <CardFooter className="flex justify-end">
                    <Button disabled={!host || isLoadingConfig} onClick={() => setActiveTab("hp")}>
                      Continue
                    </Button>
                  </CardFooter>
                </Card>
              </TabsContent>
              <TabsContent value="hp">
                <Card>
                  <CardHeader>
                    <CardDescription>
                      Default {title} configuration is set below. Configure as
                      needed.
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    <div className="max-h-[50vh] overflow-y-auto">
                      <HoneypotConfig
                        type={type}
                        config={hpConfig}
                        onChange={setHpConfig}
                      />
                    </div>
                  </CardContent>
                  <CardFooter className="flex justify-between">
                    <Button
                      onClick={handleDeployNoSave}
                      disabled={isLoadingConfig}
                    >
                      Download Install Scripts
                    </Button>
                    <Button
                      onClick={handleDeploy}
                      disabled={isLoadingConfig}
                      endIcon={<Icon className="" iconId="deploy-hp" size="5" />}
                    >
                      Deploy
                    </Button>
                  </CardFooter>
                </Card>
              </TabsContent>
              <TabsContent value="preview">
                <Card>
                  <CardHeader>
                    <CardDescription>
                      Review your deployment configuration before proceeding.
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      {/* Host Information */}
                      <div>
                        <h4 className="font-medium text-gray-900 mb-2">Host Information</h4>
                        <div className="text-sm text-gray-600 space-y-1">
                          <p><strong>Address:</strong> {host?.address || 'Not selected'}</p>
                          <p><strong>SSH Port:</strong> {host?.sshPort || 'Default'}</p>
                          <p><strong>Username:</strong> {host?.username || 'Not specified'}</p>
                        </div>
                      </div>

                      {/* Honeypot Information */}
                      <div>
                        <h4 className="font-medium text-gray-900 mb-2">Honeypot Information</h4>
                        <div className="text-sm text-gray-600 space-y-1">
                          <p><strong>Type:</strong> {type}</p>
                          <p><strong>Configuration Source:</strong> {isStoreConfig ? 'HP App Store' : 'Default'}</p>
                          {isStoreConfig && configId && (
                            <p><strong>Config ID:</strong> {configId}</p>
                          )}
                        </div>
                      </div>

                      {/* Service Configuration */}
                      <div>
                        <h4 className="font-medium text-gray-900 mb-2">Service Configuration</h4>
                        <div className="text-sm text-gray-600 space-y-1">
                          {Object.entries(hpConfig).map(([service, config]) => (
                            <div key={service} className="flex justify-between items-center">
                              <span className="capitalize">{service}:</span>
                              <span className={`px-2 py-1 rounded text-xs ${config.enabled
                                ? 'bg-green-100 text-green-700'
                                : 'bg-gray-100 text-gray-700'
                                }`}>
                                {config.enabled ? `Port ${config.port}` : 'Disabled'}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Deployment Summary */}
                      <div className="pt-4 border-t border-gray-200">
                        <h4 className="font-medium text-gray-900 mb-2">Deployment Summary</h4>
                        <div className="text-sm text-gray-600">
                          <p>Ready to deploy {title} honeypot with {Object.values(hpConfig).filter(c => c.enabled).length} enabled services.</p>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                  <CardFooter className="flex justify-between">
                    <Button onClick={() => setActiveTab("hp")}>
                      Back to Configuration
                    </Button>
                    <Button
                      onClick={handleDeploy}
                      disabled={isLoadingConfig}
                      endIcon={<Icon className="" iconId="deploy-hp" size="5" />}
                    >
                      Deploy
                    </Button>
                  </CardFooter>
                </Card>
              </TabsContent>
            </Tabs>
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
