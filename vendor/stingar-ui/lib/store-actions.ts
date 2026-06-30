'use server';

import { convertCamelToSnakeCase, convertSnakeToCamelCase } from "@/lib/utils";
import { HoneypotStore, StoreFilters, Category, Tag, InstallationData } from "@/models/store";
import { HoneypotRequest, HoneypotRequestCreate } from "@/models/hp-request";

// Normalize API_HOST by removing trailing slash if present
const API_HOST_RAW = process.env.API_HOST || "http://localhost:8000";
const API_HOST = API_HOST_RAW.replace(/\/+$/, ''); // Remove trailing slashes
const API_KEY = process.env.API_KEY || "";

// Only create URL if API_HOST is available
const API_URL = API_HOST ? new URL("/api/v2", API_HOST).href : null;

export async function getStoreData(key: string) {
    if (!API_URL) {
        throw new Error("API_HOST environment variable is not configured");
    }

    try {
        const resp = await fetch(`${API_URL}${key}`, {
            cache: "no-cache",
            headers: {
                "API-KEY": `${API_KEY}`
            },
        });
        if (!resp.ok) {
            throw new Error(`GET ${key} failed with status ${resp.status} ${resp.statusText}`);
        }
        const data = await resp.json();
        return convertSnakeToCamelCase(data);
    } catch (error: any) {
        // Handle network errors (ENOTFOUND, ECONNREFUSED, etc.)
        if (error.code === 'ENOTFOUND' || error.message?.includes('getaddrinfo ENOTFOUND') || error.cause?.code === 'ENOTFOUND') {
            const hostname = API_HOST.replace(/^https?:\/\//, '').split(':')[0];
            throw new Error(`Cannot connect to API server at ${hostname}. Please check that API_HOST is set correctly (expected: http://apiarist:8000 for Docker, or http://localhost:8000 for local development). Current value: ${API_HOST}`);
        }
        if (error.code === 'ECONNREFUSED' || error.message?.includes('ECONNREFUSED') || error.cause?.code === 'ECONNREFUSED') {
            throw new Error(`Connection refused to API server. Please check that Apiarist is running and accessible at ${API_HOST}`);
        }
        // Re-throw other errors
        throw error;
    }
}

export async function postStoreData(key: string, data: any, method: string = "POST") {
    if (!API_URL) {
        throw new Error("API_HOST environment variable is not configured");
    }

    try {
        const resp = await fetch(`${API_URL}${key}`, {
            cache: "no-cache",
            method: method,
            headers: {
                "API-KEY": `${API_KEY}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(convertCamelToSnakeCase(data)),
        });
        if (!resp.ok) {
            const result = await resp.json().catch(() => ({}));
            // Handle different error response formats
            if (resp.status === 400 || resp.status === 401) {
                if (result.errors && Array.isArray(result.errors) && result.errors.length > 0) {
                    throw new Error(result.errors[0].description || result.errors[0].title || 'Request failed');
                } else if (result.detail) {
                    throw new Error(result.detail);
                } else if (result.error) {
                    throw new Error(result.error);
                } else {
                    throw new Error(`Request failed with status ${resp.status}`);
                }
            }
            throw new Error(result.detail || result.error || `${method} ${key} failed with status ${resp.status} ${resp.statusText}`);
        }
        const result = await resp.json();
        return convertSnakeToCamelCase(result);
    } catch (error: any) {
        // Handle network errors (ENOTFOUND, ECONNREFUSED, etc.)
        if (error.code === 'ENOTFOUND' || error.message?.includes('getaddrinfo ENOTFOUND') || error.cause?.code === 'ENOTFOUND') {
            const hostname = API_HOST.replace(/^https?:\/\//, '').split(':')[0];
            throw new Error(`Cannot connect to API server at ${hostname}. Please check that API_HOST is set correctly (expected: http://apiarist:8000 for Docker, or http://localhost:8000 for local development). Current value: ${API_HOST}`);
        }
        if (error.code === 'ECONNREFUSED' || error.message?.includes('ECONNREFUSED') || error.cause?.code === 'ECONNREFUSED') {
            throw new Error(`Connection refused to API server. Please check that Apiarist is running and accessible at ${API_HOST}`);
        }
        // Re-throw other errors
        throw error;
    }
}

export async function deleteStoreData(key: string) {
    if (!API_URL) {
        throw new Error("API_HOST environment variable is not configured");
    }

    try {
        const resp = await fetch(`${API_URL}${key}`, {
            cache: "no-cache",
            method: "DELETE",
            headers: {
                "API-KEY": `${API_KEY}`,
            },
        });
        if (!resp.ok) {
            throw new Error(`DELETE ${key} failed with status ${resp.status} ${resp.statusText}`);
        }
        const data = await resp.json();
        return convertSnakeToCamelCase(data);
    } catch (error: any) {
        // Handle network errors (ENOTFOUND, ECONNREFUSED, etc.)
        if (error.code === 'ENOTFOUND' || error.message?.includes('getaddrinfo ENOTFOUND') || error.cause?.code === 'ENOTFOUND') {
            const hostname = API_HOST.replace(/^https?:\/\//, '').split(':')[0];
            throw new Error(`Cannot connect to API server at ${hostname}. Please check that API_HOST is set correctly (expected: http://apiarist:8000 for Docker, or http://localhost:8000 for local development). Current value: ${API_HOST}`);
        }
        if (error.code === 'ECONNREFUSED' || error.message?.includes('ECONNREFUSED') || error.cause?.code === 'ECONNREFUSED') {
            throw new Error(`Connection refused to API server. Please check that Apiarist is running and accessible at ${API_HOST}`);
        }
        // Re-throw other errors
        throw error;
    }
}

// Store API functions
export async function getStoreHoneypots(
    page: number = 1,
    perPage: number = 50,
    filters?: StoreFilters
): Promise<{ data: HoneypotStore[], source: string }> {
    const params = new URLSearchParams({
        page: page.toString(),
        per_page: perPage.toString(),
    });

    if (filters) {
        if (filters.category) params.append("category", filters.category);
        if (filters.hpType) params.append("hp_type", filters.hpType);
        if (filters.status) params.append("status", filters.status);
        if (filters.tags) params.append("tags", filters.tags);
        if (filters.minRating) params.append("min_rating", filters.minRating.toString());
    }

    return getStoreData(`/store/honeypots?${params}`);
}

export async function getStoreHoneypot(id: number): Promise<{ data: HoneypotStore, source: string }> {
    return getStoreData(`/store/honeypots/${id}`);
}

export async function searchStoreHoneypots(
    query: string,
    page: number = 1,
    perPage: number = 50,
    filters?: Pick<StoreFilters, 'category' | 'hpType'>
): Promise<{ data: HoneypotStore[], source: string }> {
    const params = new URLSearchParams({
        q: query,
        page: page.toString(),
        per_page: perPage.toString(),
    });

    if (filters) {
        if (filters.category) params.append("category", filters.category);
        if (filters.hpType) params.append("hp_type", filters.hpType);
    }

    return getStoreData(`/store/search?${params}`);
}

export async function installStoreHoneypot(
    id: number,
    installationData: InstallationData
): Promise<{ success: boolean; installationId?: number; message?: string }> {
    return postStoreData(`/store/honeypots/${id}`, installationData);
}

export async function getStoreCategories(): Promise<{ data: Category[], source: string }> {
    return getStoreData(`/store/categories`);
}

export async function getStoreTags(): Promise<{ data: Tag[], source: string }> {
    return getStoreData(`/store/tags`);
}

export async function getStoreInstalledHoneypots(
    page: number = 1,
    perPage: number = 50,
    status?: string
): Promise<{ data: HoneypotStore[], source: string }> {
    const params = new URLSearchParams({
        page: page.toString(),
        per_page: perPage.toString(),
    });

    if (status) {
        params.append("status", status);
    }

    return getStoreData(`/store/installed?${params}`);
}

export async function uninstallStoreHoneypot(installationId: number): Promise<{ success: boolean; message?: string }> {
    return deleteStoreData(`/store/installed/${installationId}`);
}

export async function checkStoreHealth(): Promise<{ status: string; timestamp: string }> {
    return getStoreData(`/health`);
}

export async function checkStoreAvailability(): Promise<boolean> {
    try {
        await getStoreCategories();
        return true;
    } catch (error) {
        console.warn("Store is not available:", error);
        return false;
    }
}

export async function createHoneypotRequest(
    requestData: HoneypotRequestCreate
): Promise<{ data: HoneypotRequest, source: string }> {
    const result = await postStoreData(`/store/requests`, requestData);
    // HP App Store returns object directly, wrap it in expected format
    if (result && !result.data) {
        return { data: result, source: 'remote' };
    }
    // If already wrapped, return as is
    return result;
}

export async function getHoneypotRequests(
    page: number = 1,
    perPage: number = 50,
    filters?: {
        status?: string;
        category?: string;
        priority?: string;
    }
): Promise<{ data: HoneypotRequest[], source: string }> {
    const params = new URLSearchParams({
        page: page.toString(),
        per_page: perPage.toString(),
    });

    if (filters) {
        if (filters.status) params.append("status", filters.status);
        if (filters.category) params.append("category", filters.category);
        if (filters.priority) params.append("priority", filters.priority);
    }

    const result = await getStoreData(`/store/requests?${params}`);
    // HP App Store returns a list directly, wrap it in expected format
    if (Array.isArray(result)) {
        return { data: result, source: 'remote' };
    }
    // If already wrapped, return as is
    return result;
}

export async function getHoneypotRequest(
    requestId: string
): Promise<{ data: HoneypotRequest, source: string }> {
    const result = await getStoreData(`/store/requests/${requestId}`);
    // HP App Store returns object directly, wrap it in expected format
    if (result && !result.data) {
        return { data: result, source: 'remote' };
    }
    // If already wrapped, return as is
    return result;
}
