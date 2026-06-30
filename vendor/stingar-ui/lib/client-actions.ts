// Client-side actions that don't use server actions

import { debugLog } from '@/lib/debug';

export async function cleanupInvalidConfigs(): Promise<{ message: string; deleted_count: number; deleted_configs: any[] }> {
    try {
        debugLog("Calling cleanup endpoint...");

        // Use Next.js API route instead of server action
        const response = await fetch('/api/cleanup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error("Cleanup API error:", response.status, errorText);
            throw new Error(`Cleanup failed: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        debugLog("Raw cleanup response:", data);

        // Validate response structure
        if (!data || typeof data !== 'object') {
            console.error("Invalid response structure:", data);
            throw new Error("Invalid response from cleanup endpoint");
        }

        if (!data.data || typeof data.data !== 'object') {
            console.error("Invalid data structure:", data);
            throw new Error("Invalid data structure in cleanup response");
        }

        // Ensure required fields exist with defaults
        const result = {
            message: data.data.message || "Cleanup completed",
            deleted_count: data.data.deleted_count || 0,
            deleted_configs: Array.isArray(data.data.deleted_configs) ? data.data.deleted_configs : []
        };

        debugLog("Processed cleanup result:", result);
        return result;
    }
    catch (error: any) {
        console.error("Error cleaning up invalid configs", error.message);
        console.error("Full error:", error);
        throw error;
    }
}

export async function cleanupStoreCache(options: { max_age_days?: number; force_cleanup?: boolean } = {}): Promise<{ message: string; deleted_count: number; deleted_honeypots: any[]; cleanup_type: string }> {
    try {
        debugLog("Calling store cache cleanup endpoint...", options);

        // Use Next.js API route instead of server action
        const response = await fetch('/api/store/cleanup-cache', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(options),
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error("Store cache cleanup API error:", response.status, errorText);
            throw new Error(`Store cache cleanup failed: ${response.status} ${response.statusText}`);
        }

        const data = await response.json();
        debugLog("Raw store cache cleanup response:", data);

        // Validate response structure
        if (!data || typeof data !== 'object') {
            console.error("Invalid response structure:", data);
            throw new Error("Invalid response from store cache cleanup endpoint");
        }

        if (!data.data || typeof data.data !== 'object') {
            console.error("Invalid data structure:", data);
            throw new Error("Invalid data structure in store cache cleanup response");
        }

        // Ensure required fields exist with defaults
        const result = {
            message: data.data.message || "Store cache cleanup completed",
            deleted_count: data.data.deleted_count || 0,
            deleted_honeypots: Array.isArray(data.data.deleted_honeypots) ? data.data.deleted_honeypots : [],
            cleanup_type: data.data.cleanup_type || "unknown"
        };

        debugLog("Processed store cache cleanup result:", result);
        return result;
    }
    catch (error: any) {
        console.error("Error cleaning up store cache", error.message);
        console.error("Full error:", error);
        throw error;
    }
}

export async function cleanupAll(options: { max_age_days?: number; force_cleanup?: boolean } = {}): Promise<{
    configs: { message: string; deleted_count: number; deleted_configs: any[] };
    cache: { message: string; deleted_count: number; deleted_honeypots: any[]; cleanup_type: string };
}> {
    try {
        debugLog("Starting comprehensive cleanup...", options);

        // Run both cleanup operations in parallel
        const [configsResult, cacheResult] = await Promise.all([
            cleanupInvalidConfigs(),
            cleanupStoreCache(options)
        ]);

        const result = {
            configs: configsResult,
            cache: cacheResult
        };

        debugLog("Comprehensive cleanup completed:", result);
        return result;
    }
    catch (error: any) {
        console.error("Error during comprehensive cleanup", error.message);
        console.error("Full error:", error);
        throw error;
    }
}
