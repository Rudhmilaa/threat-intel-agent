"use client";

import { DeployCard } from "@/components/deploy-card";
import { StoreConfigCard } from "@/components/store-config-card";
import { HONEYPOT_CARDS } from "@/models/honeypots";
import { Button } from "@mui/material";
import { Download } from "lucide-react";
import { Icon } from "@/components/icon";
import Link from "next/link";
import { useConfigs } from "@/lib/hooks/use-configs";

export default function Deploy() {
  const { configs, isLoading, isError, mutate } = useConfigs();

  // Built-in honeypot types that have default configurations created by build_templates.py
  const BUILTIN_HP_TYPES = ["cowrie", "dionaea", "conpot", "amun", "rdphoney"];

  // Check if a configuration is a built-in default (created by build_templates.py)
  const isBuiltinDefaultConfig = (config: any) => {
    return config.name === "default" && BUILTIN_HP_TYPES.includes(config.hp_type);
  };

  // Handle configuration deletion
  const handleConfigDelete = async (configId: number) => {
    try {
      // Optimistically remove the config from the list
      await mutate(
        (currentConfigs) =>
          currentConfigs?.filter(config => config.id !== configId) || [],
        false // Don't revalidate immediately
      );

      // Revalidate to ensure consistency with server
      await mutate();
    } catch (error) {
      console.error("Error updating configs list:", error);
    }
  };

  return (
    <div className="overflow-x-hidden max-w-full">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">Deploy Honeypot</h1>
        <Button
          component={Link}
          href="/hp-store"
          variant="contained"
          color="primary"
        >
          <Icon className="mr-2" iconId="store" size="4" />
          Download Honeypots
        </Button>
      </div>

      {/* Default Honeypots Section */}
      <div className="mb-8 p-6 bg-gray-50 rounded-lg border border-gray-200 overflow-x-hidden">
        <h3 className="text-lg font-semibold mb-4 text-gray-800">Default Honeypots</h3>
        <p className="text-sm text-gray-600 mb-4">
          Pre-installed honeypot types that work independently of the Honeypot Store. These are always available for deployment.
        </p>
        <div className="flex flex-wrap flex-1 gap-14 max-w-full">
          {HONEYPOT_CARDS.map((card, i) => (
            <DeployCard
              key={i}
              type={card.type}
              title={card.title}
              description={card.description}
            />
          ))}
        </div>
      </div>

      {/* Store-Installed Honeypots Section */}
      {configs.filter(config => config && config.hp_type && !isBuiltinDefaultConfig(config)).length > 0 && (
        <div className="mt-8 p-6 bg-blue-50 rounded-lg border border-blue-200 overflow-x-hidden">
          <h3 className="text-lg font-semibold mb-4 text-blue-800">Custom Honeypot Configurations</h3>
          <p className="text-sm text-gray-600 mb-4">
            These are custom configurations installed from the Honeypot Store. They may include enhanced settings,
            additional protocols, or specialized configurations for specific use cases.
          </p>
          <div className="flex flex-wrap flex-1 gap-14 max-w-full">
            {configs
              .filter(config => config && config.hp_type) // Filter out invalid configs
              .filter(config => !isBuiltinDefaultConfig(config)) // Filter out built-in default configurations to avoid duplication
              .map((config) => (
                <StoreConfigCard
                  key={config.id}
                  config={config}
                  onDelete={handleConfigDelete}
                />
              ))}
          </div>
        </div>
      )}

      {/* Loading State */}
      {isLoading && (
        <div className="mt-8 overflow-x-hidden">
          <h3 className="text-lg font-semibold mb-4 text-blue-800">Store-Installed Honeypots</h3>
          <div className="flex flex-wrap flex-1 gap-14 max-w-full">
            {[1, 2, 3].map((i) => (
              <div key={i} className="w-full min-w-0 max-w-[350px] sm:w-[350px] h-[200px] bg-gray-200 animate-pulse rounded-lg"></div>
            ))}
          </div>
        </div>
      )}

      {/* Error State */}
      {isError && (
        <div className="mt-8">
          <h3 className="text-lg font-semibold mb-4 text-blue-800">Store-Installed Honeypots</h3>
          <div className="text-red-600">
            Failed to load store-installed honeypots. Please try refreshing the page.
          </div>
        </div>
      )}
    </div>
  );
}
