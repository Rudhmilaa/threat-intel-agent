/**
 * Configuration templates from store installations
 */

export type StoreConfig = {
    id: number;
    name: string;
    hp_type: string;
    hp_options: Record<string, any>;
    created: string;
    updated: string;
    source: 'store';
};

export type StoreConfigArray = StoreConfig[];

export type StoreConfigResponse = {
    data: StoreConfigArray;
};

export type StoreConfigSingleResponse = {
    data: StoreConfig;
};
