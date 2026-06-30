import useSWR from 'swr';
import { getConfigs } from '@/lib/actions';
import { StoreConfig } from '@/models/configs';
import { HoneypotType } from '@/models/honeypots';

export function useConfigs() {
    const { data, error, isLoading, mutate } = useSWR<StoreConfig[]>(
        '/configs',
        getConfigs,
        {
            revalidateOnFocus: false,
            revalidateOnReconnect: true,
            refreshInterval: 300000, // Refresh every 5 minutes
        }
    );

    // Filter out invalid configs and add safety checks
    const filteredConfigs = (data || []).filter(config => {
        // Validate config has required fields
        if (!config || typeof config !== 'object') {
            console.warn('useConfigs: Invalid config object:', config);
            return false;
        }

        // Check for both snake_case and camelCase field names
        const configAny = config as any;
        const hasHpType = config.hp_type || configAny.hpType;

        if (!config.id || !config.name || !hasHpType) {
            console.warn('useConfigs: Config missing required fields:', config);
            return false;
        }

        // Normalize to snake_case if needed
        if (configAny.hpType && !config.hp_type) {
            (config as any).hp_type = configAny.hpType;
        }
        if (configAny.hpOptions && !config.hp_options) {
            (config as any).hp_options = configAny.hpOptions;
        }

        // Keep all valid store configs - they represent custom configurations
        // even if they have the same hp_type as defaults
        return true;
    });

    return {
        configs: filteredConfigs,
        isLoading,
        isError: error,
        mutate,
    };
}
