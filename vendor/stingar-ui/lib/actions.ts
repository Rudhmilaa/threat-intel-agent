'use server';

import { readFileSync } from "fs";
import { convertCamelToSnakeCase, convertSnakeToCamelCase } from "@/lib/utils";
import { Host, HostArraySchema, HostSchema } from "@/models/hosts";
import { AuthKey, AuthKeySchema, AuthKeysArraySchema } from "@/models/authKeys";
import { DeploymentArraySchema, DeploymentSchema, Deployments } from "@/models/deployments";
import { SensorArraySchema } from "@/models/sensors";
import { SessionArraySchema, SessionSchema } from "@/models/sessions";
import { BlockedIP, BlocklistArraySchema, BlocklistSchema, Settings } from "@/models/honeycomb";
import { verifySession } from "@/app/auth/session";
import { StoreConfig, StoreConfigArray, StoreConfigResponse, StoreConfigSingleResponse } from "@/models/configs";
import { debugLog } from "@/lib/debug";

// Normalize API_HOST by removing trailing slash if present
const API_HOST_RAW = process.env.API_HOST || 'http://localhost:8000';
const API_HOST = API_HOST_RAW.replace(/\/+$/, ''); // Remove trailing slashes
const API_URL = `${API_HOST}/api/v2`;

// Read API_KEY at runtime from stingar.env (avoids Docker env_file being read at compose parse time, before apiarist writes it)
function getApiKey(): string {
    const fromEnv = process.env.API_KEY;
    if (fromEnv) return fromEnv;
    const envPath = process.env.STINGAR_ENV_PATH || '/app/stingar.env';
    try {
        const content = readFileSync(envPath, 'utf8');
        const m = content.match(/^API_KEY=(.*)$/m);
        return m ? m[1].trim() : '';
    } catch {
        return '';
    }
}

/**
 * Sanitizes sensitive data from objects before logging
 * Removes or redacts password fields and other sensitive information
 */
function sanitizeLogData(data: any): any {
    if (!data || typeof data !== 'object') {
        return data;
    }

    if (Array.isArray(data)) {
        return data.map(item => sanitizeLogData(item));
    }

    const sanitized = { ...data };
    const sensitiveFields = ['password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey'];

    // Case-insensitive matching for sensitive fields
    for (const key in sanitized) {
        const keyLower = key.toLowerCase();
        if (sensitiveFields.some(field => keyLower === field.toLowerCase())) {
            sanitized[key] = '[REDACTED]';
        } else if (sanitized[key] && typeof sanitized[key] === 'object') {
            // Recursively sanitize nested objects
            sanitized[key] = sanitizeLogData(sanitized[key]);
        }
    }

    return sanitized;
}

async function getData(key: string) {
    const fullUrl = `${API_URL}${key}`;

    // Debug logging (commented out for production)
    // console.log('getData: Making request to:', fullUrl);
    // console.log('getData: API_KEY is set:', !!API_KEY);
    // console.log('getData: API_KEY length:', API_KEY.length);

    const resp = await fetch(fullUrl, {
        cache: "no-cache",
        headers: {
            "API-KEY": `${getApiKey()}`
        },
    });

    // Debug logging (commented out for production)
    // console.log('getData: Response status:', resp.status);
    // console.log('getData: Response ok:', resp.ok);

    if (!resp.ok) {
        const errorText = await resp.text();
        // console.error('getData: Error response body:', errorText);
        throw new Error(`GET ${key} failed with status ${resp.status} ${resp.statusText}: ${errorText}`);
    }
    const data = await resp.json();
    return convertSnakeToCamelCase(data);
}

async function getDataBlob(key: string) {
    const resp = await fetch(`${API_URL}${key}`, {
        cache: "no-cache",
        headers: {
            "API-KEY": `${getApiKey()}`
        },
    });
    if (!resp.ok) {
        throw new Error(`GET ${key} failed with status ${resp.status} ${resp.statusText}`);
    }
    const data = await resp.blob();
    return data;
}

async function postData(key: string, data: any, method: string = "POST") {
    const resp = await fetch(`${API_URL}${key}`, {
        cache: "no-cache",
        method: method,
        headers: {
            "API-KEY": `${getApiKey()}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify(convertCamelToSnakeCase(data)),
    });
    if (!resp.ok) {
        let errorMessage = `POST ${key} failed with status ${resp.status} ${resp.statusText}`;
        // Clone response so we can read it multiple times if needed
        const respClone = resp.clone();
        try {
            const result = await resp.json();
            // Log full error details for 500 errors to help debug backend issues
            if (resp.status === 500) {
                console.error(`Backend Server Error (500) for ${key}:`, result);
                errorMessage = `Backend server error (${resp.status}): ${JSON.stringify(result)}`;
            } else {
                console.error(`API Error Response (${resp.status}):`, result);
            }
            console.error(`Request URL: ${API_URL}${key}`);
            console.error(`Request Data:`, sanitizeLogData(data));

            if (resp.status === 400) {
                if (result.errors && Array.isArray(result.errors) && result.errors.length > 0) {
                    const firstError = result.errors[0];
                    errorMessage = firstError.description || firstError.message || firstError.detail || JSON.stringify(firstError) || "Bad request";
                } else if (result.detail) {
                    errorMessage = result.detail;
                } else if (result.message) {
                    errorMessage = result.message;
                } else {
                    errorMessage = `Bad request: ${JSON.stringify(result)}`;
                }
            } else if (resp.status === 500) {
                // Handle 500 errors - backend server errors
                errorMessage = `Backend server error (500): ${result.detail || result.message || JSON.stringify(result) || 'Internal server error'}`;
            } else if (resp.status === 401) {
                if (result.errors && Array.isArray(result.errors) && result.errors.length > 0) {
                    const firstError = result.errors[0];
                    const title = firstError.title || "";
                    const description = firstError.description || firstError.message || "Unauthorized";
                    // Format: "Title - Description" if title exists, otherwise just description
                    errorMessage = title ? `${title} - ${description}` : description;
                } else if (result.detail) {
                    errorMessage = result.detail;
                } else {
                    errorMessage = "Unauthorized";
                }
            } else {
                if (result.detail) {
                    errorMessage = `${errorMessage}: ${result.detail}`;
                } else if (result.message) {
                    errorMessage = `${errorMessage}: ${result.message}`;
                }
            }
        } catch (parseError) {
            // If JSON parsing fails, try to get text response from cloned response
            try {
                const textResponse = await respClone.text();
                console.error(`API Error Response (${resp.status}) - Non-JSON:`, textResponse);
                console.error(`Request URL: ${API_URL}${key}`);
                console.error(`Request Data:`, sanitizeLogData(data));
                errorMessage = `${errorMessage}: ${textResponse || 'No error details available'}`;
            } catch (textError) {
                console.error(`Failed to read error response:`, textError);
                console.error(`Request URL: ${API_URL}${key}`);
                console.error(`Request Data:`, sanitizeLogData(data));
            }
        }
        throw new Error(errorMessage);
    }
    const result = await resp.json();
    return convertSnakeToCamelCase(result);
}

async function postDataBlob(key: string, data: any, method: string = "POST") {
    const resp = await fetch(`${API_URL}${key}`, {
        cache: "no-cache",
        method: method,
        headers: {
            "API-KEY": `${getApiKey()}`,
            "Content-Type": "application/json",
        },
        body: JSON.stringify(convertCamelToSnakeCase(data)),
    });
    if (!resp.ok) {
        if (resp.status === 400) {
            const result = await resp.json();
            if (result.errors && Array.isArray(result.errors) && result.errors.length > 0) {
                throw new Error(result.errors[0].description || result.errors[0].message || "Bad request");
            }
            throw new Error("Bad request");
        }
        if (resp.status === 401) {
            const result = await resp.json();
            if (result.errors && Array.isArray(result.errors) && result.errors.length > 0) {
                throw new Error(result.errors[0].description || result.errors[0].message || "Unauthorized");
            }
            throw new Error("Unauthorized");
        }
        throw new Error(`POST ${key} failed with status ${resp.status} ${resp.statusText}`);
    }
    return resp.blob();
}

async function deleteData(key: string) {
    const resp = await fetch(`${API_URL}${key}`, {
        cache: "no-cache",
        method: "DELETE",
        headers: {
            "API-KEY": `${getApiKey()}`,
        },
    });
    if (!resp.ok) {
        throw new Error(`DELETE ${key} failed with status ${resp.status} ${resp.statusText}`);
    }
    const result = await resp.json();
    return convertSnakeToCamelCase(result);
}

// Create user
export async function createUser(data: any): Promise<any> {
    try {
        const result = await postData("/users", data);
        return result.data;
    }
    catch (error: any) {
        console.error("Error creating user", error.message);
        return { error: error.message };
    }
}

// Update user
export async function updateUser(data: any): Promise<any> {
    try {
        const { isAuth, userId } = await verifySession();
        if (!isAuth) {
            return { error: "Unauthenticated" };
        }
        const result = await postData(`/users/${userId}`, data, "PUT");
        return result.data;
    }
    catch (error: any) {
        console.error("Error updating user", error.message);
        return { error: error.message };
    }
}

export async function updateToken(data: any): Promise<any> {
    try {
        const { isAuth, userId } = await verifySession();
        if (!isAuth) {
            return { error: "Unauthenticated" };
        }
        const result = await postData(`/users/${userId}/token`, data, "PUT");
        return result.data;
    }
    catch (error: any) {
        console.error("Error updating user", error.message);
        return { error: error.message };
    }
}

export async function getUser(key: string): Promise<any> {
    try {
        const { isAuth, userId } = await verifySession();
        if (!isAuth) {
            return { error: "Unauthenticated" };
        }
        const data = await getData(`/users/${userId}`);
        return data.data;
    }
    catch (error: any) {
        console.error("Error fetching user", error.message);
        throw error;
    }
}

export async function getUsers(key: string): Promise<any> {
    try {
        const { isAuth, userId } = await verifySession();
        if (!isAuth) {
            return { error: "Unauthenticated" };
        }
        const data = await getData(key);
        return data.data;
    }
    catch (error: any) {
        console.error("Error fetching user", error.message);
        throw error;
    }
}

export async function deleteUser(id: string): Promise<any> {
    try {
        const data = await deleteData(`/users/${id}`);
        return data.data;
    }
    catch (error: any) {
        console.error("Error deleting user", error.message);
        throw error;
    }
}

export async function authUser(data: any): Promise<any> {
    try {
        const result = await postData("/authenticate_user", data);
        return result.data;
    }
    catch (error: any) {
        console.error("Error authenticating user:", error.message);

        // Handle 500 errors from backend (may indicate backend bug)
        if (error.message.includes("500") || error.message.includes("Internal Server Error")) {
            console.error("Backend server error during authentication. This may indicate a backend configuration issue.");
            return { error: "Authentication service error. Please contact your administrator." };
        }

        // Handle 401/403 errors (authentication failures)
        // The error message from postData already extracts the description from the API response
        // Format: "Authentication Failed - Incorrect username or password."
        if (error.message.includes("401") || error.message.includes("403") || error.message.includes("Unauthorized") ||
            error.message.toLowerCase().includes("incorrect username or password")) {
            // Extract the error message, defaulting to the standard format
            let errorMsg = error.message;
            if (error.message.toLowerCase().includes("incorrect username or password")) {
                errorMsg = "Authentication Failed - Incorrect username or password.";
            } else if (error.message.includes(":")) {
                // If error message has format "401: description", extract description
                const parts = error.message.split(":");
                if (parts.length > 1) {
                    errorMsg = `Authentication Failed - ${parts.slice(1).join(":").trim()}`;
                }
            } else {
                errorMsg = "Authentication Failed - Incorrect username or password.";
            }
            return { error: errorMsg, isAuthFailure: true };
        }

        // Generic error for other cases
        return { error: "Authentication Failed - Incorrect username or password.", isAuthFailure: true };
    }
}

export async function getKeys(key: string): Promise<AuthKey[]> {
    try {
        const data = await getData(key);
        return AuthKeysArraySchema.parse(data.data);
    }
    catch (error: any) {
        console.error("Error fetching keys", error.message);
        throw error;
    }
}

export async function createKey(name: string): Promise<AuthKey> {
    try {
        const data = await postData("/authkeys", { name: name });
        return AuthKeySchema.parse(data.data);
    }
    catch (error: any) {
        console.error("Error creating key", error.message);
        throw error;
    }
}

export async function deleteKey(id: string): Promise<AuthKey> {
    try {
        const data = await deleteData(`/authkeys/${id}`);
        return AuthKeySchema.parse(data.data);
    }
    catch (error: any) {
        console.error("Error deleting key", error.message);
        throw error;
    }
}

export async function getHosts(key: string): Promise<Omit<Host, "authkeyName">[]> {
    try {
        const data = await getData(key);
        return HostArraySchema.parse(data.data);
    }
    catch (error: any) {
        console.error("Error fetching hosts", error.message);
        throw error;
    }
}

export async function createHost(data: any): Promise<Omit<Host, "authkeyName">> {
    try {
        const result = await postData("/hosts", data);
        return HostSchema.parse(result);
    }
    catch (error: any) {
        console.error("Error creating host", error.message);
        throw error;
    }
}

export async function updateHost(hostId: string, data: any): Promise<Omit<Host, "authkeyName">> {
    try {
        const result = await postData(`/hosts/${hostId}`, data, "PUT");
        return HostSchema.parse(result.data);
    }
    catch (error: any) {
        console.error("Error updating host", error.message);
        throw error;
    }
}

export async function deleteHost(id: string): Promise<Omit<Host, "authkeyName">> {
    try {
        const data = await deleteData(`/hosts/${id}`);
        return HostSchema.parse(data.data);
    }
    catch (error: any) {
        console.error("Error deleting host", error.message);
        throw error;
    }
}

export async function getDeployments(key: string): Promise<Deployments[]> {
    try {
        const data = await getData(key);
        return DeploymentArraySchema.parse(data.data);
    }
    catch (error: any) {
        console.error("Error fetching deployments", error.message);
        throw error;
    }
}

export async function getDeploymentLogs(key: string): Promise<any> {
    try {
        const data = await getData(key);
        return data.data.documents;
    }
    catch (error: any) {
        console.error("Error fetching deployment", error.message);
        throw error;
    }
}

export async function getSensors(key: string): Promise<any> {
    try {
        const data = await getData(key);
        return { data: SensorArraySchema.parse(data.data.documents), count: data.data.count };
    }
    catch (error: any) {
        console.error("Error fetching sensors", error.message);
        throw error;
    }
}

// Debug mode flag - set to true to enable debug logging
const DEBUG_MODE = process.env.NODE_ENV === 'development' || process.env.DEBUG === 'true';

// Helper function to transform API response with defaults
function transformSessionData(apiSession: any) {
    // Log missing critical fields for debugging
    const missingFields = [];
    if (!apiSession.id) missingFields.push('id');
    if (!apiSession.app) missingFields.push('app');
    if (!apiSession.sensor?.uuid) missingFields.push('sensor.uuid');
    if (!apiSession.srcIp) missingFields.push('srcIp');

    if (missingFields.length > 0) {
        debugLog('Session missing fields:', missingFields, 'Session ID:', apiSession.id);
    }

    // Debug log the actual API response structure
    debugLog('API Session data:', {
        id: apiSession.id,
        srcIp: apiSession.srcIp,
        srcPort: apiSession.srcPort,
        dstIp: apiSession.dstIp,
        dstPort: apiSession.dstPort,
        app: apiSession.app,
        protocol: apiSession.protocol,
        fluentdTag: apiSession.fluentdTag,
        allKeys: Object.keys(apiSession)
    });

    // Handle both snake_case and camelCase field names (defensive programming)
    const srcIp = apiSession.srcIp || apiSession.src_ip || "";
    const srcPort = apiSession.srcPort ?? apiSession.src_port ?? null;
    const dstIp = apiSession.dstIp || apiSession.dst_ip || "";
    const dstPort = apiSession.dstPort ?? apiSession.dst_port ?? null;

    // Handle fluentdTag field mapping
    const fluentdTag = apiSession.fluentdTag || apiSession.fluentd_tag || "";

    // Extract hpData for geo field processing
    const hpData = apiSession.hpData || apiSession.hp_data || {};


    // Extract geo fields from hpData - handle various field name formats
    const geoData = {
        geopoint: hpData.geopoint || undefined,
        geoPoint: hpData.geoPoint || undefined,
        // Handle different country field names
        country: hpData.country || hpData.geoCc || hpData.country_code || hpData.countryCode || undefined,
        // Handle different city field names  
        city: hpData.city || hpData.geoCity || hpData.geo_city || undefined,
        coordinates: hpData.coordinates || undefined,
        // Extract lat/lon from geopoint if it's an object
        latitude: hpData.latitude || (hpData.geopoint && hpData.geopoint.lat) || undefined,
        longitude: hpData.longitude || (hpData.geopoint && hpData.geopoint.lon) || undefined,
        // Additional geo fields that might be present
        location: hpData.location || undefined,
        geo: hpData.geo || undefined,
        geoip: hpData.geoip || undefined,
        geolocation: hpData.geolocation || undefined,
        // Store original fields for debugging
        geoCity: hpData.geoCity || undefined,
        geoCc: hpData.geoCc || undefined
    };


    const transformed = {
        id: apiSession.id || "",
        app: apiSession.app || "",
        srcIp: srcIp,
        srcPort: srcPort,
        dstIp: dstIp,
        dstPort: dstPort,
        startTime: apiSession.startTime || apiSession.start_time || new Date().toISOString(),
        endTime: apiSession.endTime || apiSession.end_time || new Date().toISOString(),
        protocol: apiSession.protocol || null,
        "@timestamp": apiSession["@timestamp"] || new Date().toISOString(),
        fluentdTag: fluentdTag,
        sensor: {
            hostname: apiSession.sensor?.hostname || "",
            uuid: apiSession.sensor?.uuid || "",
            asn: apiSession.sensor?.asn || null,
            tags: apiSession.sensor?.tags || {}
        },
        hpData: hpData,
        geoData: geoData,
        c2_host: apiSession.c2_host ?? apiSession.c2Host ?? undefined,
        outcome_category:
            apiSession.outcome_category ||
            apiSession.outcomeCategory ||
            hpData?.enrichment?.scanner_lite?.outcome_category ||
            hpData?.investigation?.category ||
            undefined,
        outcome_summary:
            apiSession.outcome_summary ||
            apiSession.outcomeSummary ||
            hpData?.enrichment?.scanner_lite ||
            undefined,
    };

    return transformed;
}

export async function getSessions(key: string): Promise<any> {
    try {
        // Debug logging (commented out for production)
        // console.log('getSessions: Starting with key:', key);

        const data = await getData(key);

        // Debug logging (commented out for production)
        // console.log('getSessions: Got data from backend:', {
        //     hasData: !!data?.data,
        //     hasDocuments: !!data?.data?.documents,
        //     documentsLength: data?.data?.documents?.length,
        //     hasCount: !!data?.data?.count,
        //     count: data?.data?.count
        // });

        // Transform and provide defaults for missing fields
        // console.log('getSessions: About to transform documents');
        const transformedDocuments = data.data.documents.map(transformSessionData);
        // console.log('getSessions: Transformed documents, length:', transformedDocuments.length);

        // console.log('getSessions: About to parse with schema');
        const parsedData = SessionArraySchema.parse(transformedDocuments);
        // console.log('getSessions: Schema parsing successful, length:', parsedData.length);

        const result = {
            data: parsedData,
            count: data.data.count
        };

        // Debug logging (commented out for production)
        // console.log('getSessions: Returning result:', {
        //     dataLength: result.data.length,
        //     count: result.count
        // });

        return result;
    }
    catch (error: any) {
        console.error("Error fetching sessions", error.message);
        // Debug logging (commented out for production)
        // console.error("getSessions: Error stack:", error.stack);
        throw error;
    }
}

export async function getSession(key: string): Promise<any> {
    try {
        const data = await getData(key);
        const transformedSession = transformSessionData(data.data);
        return SessionSchema.parse(transformedSession);
    }
    catch (error: any) {
        console.error("Error fetching session", error.message);
        throw error;
    }
}

export async function createDeployment(data: any): Promise<Deployments> {
    try {
        // Validate deployment data before sending
        if (!data || typeof data !== 'object') {
            throw new Error("Invalid deployment data: data must be an object");
        }

        if (!data.hp_type || data.hp_type.trim() === '') {
            throw new Error("Invalid deployment data: hp_type is required and cannot be empty");
        }

        if (!data.hp_options || typeof data.hp_options !== 'object') {
            throw new Error("Invalid deployment data: hp_options must be an object");
        }

        // Ensure hp_options is not empty
        if (Object.keys(data.hp_options).length === 0) {
            throw new Error("Invalid deployment data: hp_options cannot be empty");
        }

        debugLog("Creating deployment with data:", data);
        const result = await postData("/deployments", data);
        debugLog("createDeployment result:", result);
        debugLog("result.data:", result.data);
        return DeploymentSchema.parse(result.data);
    }
    catch (error: any) {
        console.error("Error creating deployment", error.message);
        console.error("Full error:", error);
        throw error;
    }
}

export async function createComposeNoSave(data: any): Promise<any> {
    try {
        // Validate deployment data before sending
        if (!data || typeof data !== 'object') {
            throw new Error("Invalid deployment data: data must be an object");
        }

        if (!data.hp_type || data.hp_type.trim() === '') {
            throw new Error("Invalid deployment data: hp_type is required and cannot be empty");
        }

        if (!data.hp_options || typeof data.hp_options !== 'object') {
            throw new Error("Invalid deployment data: hp_options must be an object");
        }

        // Ensure hp_options is not empty
        if (Object.keys(data.hp_options).length === 0) {
            throw new Error("Invalid deployment data: hp_options cannot be empty");
        }

        debugLog("Creating compose with data:", data);
        const result = await postDataBlob("/deployments/compose", data);
        return result;
    }
    catch (error: any) {
        console.error("Error creating compose", error.message);
        throw error;
    }
}

export async function createEnvNoSave(data: any): Promise<any> {
    try {
        // Validate deployment data before sending
        if (!data || typeof data !== 'object') {
            throw new Error("Invalid deployment data: data must be an object");
        }

        if (!data.hp_type || data.hp_type.trim() === '') {
            throw new Error("Invalid deployment data: hp_type is required and cannot be empty");
        }

        if (!data.hp_options || typeof data.hp_options !== 'object') {
            throw new Error("Invalid deployment data: hp_options must be an object");
        }

        // Ensure hp_options is not empty
        if (Object.keys(data.hp_options).length === 0) {
            throw new Error("Invalid deployment data: hp_options cannot be empty");
        }

        debugLog("Creating env with data:", data);
        const result = await postDataBlob("/deployments/env", data);
        return result;
    }
    catch (error: any) {
        console.error("Error creating env", error.message);
        throw error;
    }
}

export async function getBlocklist(key: string): Promise<BlockedIP[]> {
    try {
        const data = await getData(key);
        return BlocklistArraySchema.parse(data.data);
    }
    catch (error: any) {
        console.error("Error fetching blocklist", error.message);
        throw error;
    }
}

export async function createBlockedIP(address: string | string[]): Promise<any> {
    try {
        const result = await postData("/blocklist", { address: address });
        return result.addedAddresses;
    }
    catch (error: any) {
        console.error("Error creating blocked IP", error.message);
        throw error;
    }
}

export async function deleteBlockedIP(id: number): Promise<any> {
    try {
        const data = await deleteData(`/blocklist/${id}`);
        return data.data;
    }
    catch (error: any) {
        console.error("Error deleting blocked IP", error.message);
        throw error;
    }
}

export async function getSettings(key: string): Promise<Settings> {
    try {
        const data = await getData(key);
        return data.data;
    }
    catch (error: any) {
        console.error("Error fetching settings", error.message);
        throw error;
    }
}

export async function enableHoneycomb(enable: Boolean): Promise<Settings> {
    try {
        const data = await postData("/honeycomb", { enable: enable });
        return data.data;
    }
    catch (error: any) {
        console.error("Error enabling honeycomb", error.message);
        throw error;
    }
}

export async function getDeploymentCompose(id: string): Promise<any> {
    try {
        const data = await getDataBlob(`/deployments/${id}/compose`);
        return data;
    }
    catch (error: any) {
        console.error("Error fetching deployment compose", error.message);
        throw error;
    }
}

export async function getDeploymentEnv(id: string): Promise<any> {
    try {
        const data = await getDataBlob(`/deployments/${id}/env`);
        return data;
    }
    catch (error: any) {
        console.error("Error fetching deployment env", error.message);
        throw error;
    }
}

export async function getConfigs(key: string): Promise<StoreConfig[]> {
    try {
        const data = await getData(key);

        // Safety check for data structure
        if (!data || typeof data !== 'object') {
            console.error("getConfigs: Invalid response data:", data);
            return [];
        }

        if (!data.data || !Array.isArray(data.data)) {
            console.error("getConfigs: Invalid data.data format:", data.data);
            return [];
        }

        // Validate each config object
        const validConfigs = data.data.filter((config: any) => {
            if (!config || typeof config !== 'object') {
                debugLog("getConfigs: Invalid config object:", config);
                return false;
            }

            // Check for both snake_case and camelCase field names
            const hasHpType = config.hp_type || config.hpType;
            const hasHpOptions = config.hp_options || config.hpOptions;

            if (!config.id || !config.name || !hasHpType) {
                debugLog("getConfigs: Config missing required fields:", config);
                return false;
            }

            // Normalize the config object to use snake_case
            if (config.hpType && !config.hp_type) {
                config.hp_type = config.hpType;
            }
            if (config.hpOptions && !config.hp_options) {
                config.hp_options = config.hpOptions;
            }

            // Ensure hp_type is not empty
            if (!config.hp_type || config.hp_type.trim() === '') {
                debugLog("getConfigs: Config has empty hp_type:", config);
                return false;
            }

            return true;
        });

        return validConfigs as StoreConfig[];
    }
    catch (error: any) {
        console.error("Error fetching configs", error.message);
        // Return empty array instead of throwing to prevent UI crashes
        return [];
    }
}

export async function getConfig(id: string): Promise<StoreConfig> {
    try {
        const data = await getData(`/configs/${id}`);
        return data.data as StoreConfig;
    }
    catch (error: any) {
        console.error("Error fetching config", error.message);
        throw error;
    }
}

export async function deleteConfig(id: string): Promise<any> {
    try {
        const result = await deleteData(`/configs/${id}`);
        return result;
    }
    catch (error: any) {
        console.error("Error deleting config", error.message);
        throw error;
    }
}

// Cache validation functions
export async function validateCache(maxAgeHours: number = 24): Promise<{
    total_cached: number;
    fresh_count: number;
    stale_count: number;
    stale_honeypots: any[];
    freshness_percentage: number;
    validation_timestamp: string;
    max_age_hours: number;
}> {
    try {
        const data = await getData(`/cache/validate?max_age_hours=${maxAgeHours}`);
        return data.data;
    } catch (error: any) {
        console.error("Error validating cache:", error);
        throw new Error("Failed to validate cache: " + (error.message || "Unknown error"));
    }
}

export async function getCacheStatistics(): Promise<{
    total_cached: number;
    oldest_cache_age_hours: number | null;
    newest_cache_age_hours: number | null;
    average_cache_age_hours: number | null;
    cache_timestamp: string;
}> {
    try {
        const data = await getData('/cache/statistics');
        return data.data;
    } catch (error: any) {
        console.error("Error getting cache statistics:", error);
        throw new Error("Failed to get cache statistics: " + (error.message || "Unknown error"));
    }
}

export async function validateSpecificHoneypot(remoteId: string, maxAgeHours: number = 24): Promise<{
    remote_id: string;
    found: boolean;
    is_stale: boolean | null;
    age_hours: number | null;
    last_updated: string | null;
    validation_timestamp: string;
}> {
    try {
        const data = await getData(`/cache/validate/${remoteId}?max_age_hours=${maxAgeHours}`);
        return data.data;
    } catch (error: any) {
        console.error("Error validating specific honeypot:", error);
        throw new Error("Failed to validate honeypot: " + (error.message || "Unknown error"));
    }
}

export async function getStaleHoneypots(maxAgeHours: number = 24): Promise<{
    stale_honeypots: any[];
    count: number;
    max_age_hours: number;
    timestamp: string;
}> {
    try {
        const data = await getData(`/cache/stale?max_age_hours=${maxAgeHours}`);
        return data.data;
    } catch (error: any) {
        console.error("Error getting stale honeypots:", error);
        throw new Error("Failed to get stale honeypots: " + (error.message || "Unknown error"));
    }
}

export async function cleanupInvalidConfigs(): Promise<{ message: string; deleted_count: number; deleted_configs: any[] }> {
    try {
        debugLog("Calling cleanup endpoint...");
        const data = await postData("/configs", { action: "cleanup_invalid" });
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

// Check for admin user without authentication
// Returns { admin, errorType } where errorType is 'unauthorized' | 'not_found' | 'server_error' | 'network' | null
export async function checkAdminUser(): Promise<{ admin: any; errorType: string | null }> {
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000);

        const resp = await fetch(`${API_URL}/users`, {
            cache: "no-cache",
            headers: {
                "API-KEY": `${getApiKey()}`
            },
            signal: controller.signal,
        });

        clearTimeout(timeoutId);

        if (!resp.ok) {
            if (resp.status === 401 || resp.status === 403) {
                return { admin: null, errorType: 'unauthorized' };
            }
            if (resp.status >= 500) {
                return { admin: null, errorType: 'server_error' };
            }
            throw new Error(`Failed to check admin user with status ${resp.status}`);
        }

        const data = await resp.json();
        const users = convertSnakeToCamelCase(data).data;
        const admin = Array.isArray(users) ? users.find((user: any) => user.username === "admin") : null;
        if (!admin) {
            return { admin: null, errorType: 'not_found' };
        }
        return { admin, errorType: null };
    } catch (error: any) {
        if (error.name === 'AbortError' || error.message?.includes('fetch failed') || error.message?.includes('ECONNREFUSED')) {
            return { admin: null, errorType: 'network' };
        }
        if (process.env.NODE_ENV === 'production') {
            console.error("Error checking admin user:", error);
            throw error;
        }
        return { admin: null, errorType: 'network' };
    }
}

// Set initial admin password
export async function setInitialAdminPassword(data: any): Promise<any> {
    try {
        // Direct API call without authentication check
        const result = await postData(`/users/${data.id}`, data, "PUT");
        return result.data;
    }
    catch (error: any) {
        console.error("Error setting initial admin password:", error.message);
        return { error: error.message };
    }
}

// Get store count
export async function getStoreCount(): Promise<{ data: { count: number }, source: string }> {
    try {
        return await getData('/store/honeypots/count');
    }
    catch (error: any) {
        console.error("Error fetching store count:", error.message);
        throw error;
    }
}

// IDS Rules - extract signatures from honeypot data
export type IdsRulesFormat = 'suricata' | 'snort';

export interface IdsRulesParams {
    fromDate?: string;
    toDate?: string;
    app?: 'cowrie' | 'dionaea' | 'all';
    ruleTypes?: string;
    limit?: number;
    format?: IdsRulesFormat;
}

export interface IdsSignature {
    type: string;
    hash: string;
    source: string;
    count: number;
    firstSeen: string;
    srcIps?: string[];
}

export async function getIdsRulesSignatures(params: IdsRulesParams = {}): Promise<{
    data: { signatures: IdsSignature[]; summary: { totalHassh: number; totalJa3: number; totalJa3s: number; dateRange: { from: string; to: string } } };
}> {
    const searchParams = new URLSearchParams();
    if (params.fromDate) searchParams.set('from_date', params.fromDate);
    if (params.toDate) searchParams.set('to_date', params.toDate);
    if (params.app && params.app !== 'all') searchParams.set('app', params.app);
    if (params.ruleTypes) searchParams.set('rule_types', params.ruleTypes);
    if (params.limit) searchParams.set('limit', String(params.limit));
    const query = searchParams.toString();
    const key = `/ids-rules${query ? '?' + query : ''}`;
    return await getData(key);
}

export async function getIdsRulesExportBlob(params: IdsRulesParams = {}): Promise<Blob> {
    const searchParams = new URLSearchParams();
    if (params.fromDate) searchParams.set('from_date', params.fromDate);
    if (params.toDate) searchParams.set('to_date', params.toDate);
    if (params.app && params.app !== 'all') searchParams.set('app', params.app);
    if (params.ruleTypes) searchParams.set('rule_types', params.ruleTypes);
    if (params.limit) searchParams.set('limit', String(params.limit));
    if (params.format) searchParams.set('format', params.format);
    const query = searchParams.toString();
    const key = `/ids-rules/export${query ? '?' + query : ''}`;
    return await getDataBlob(key);
}

export async function getIdsRulesStatus(): Promise<{
    data: {
        lastGenerated: string | null;
        totalHassh: number;
        totalJa3: number;
        totalJa3s: number;
        totalSshSoftware: number;
        feedUrl: string;
        feedUrlSuricata: string;
        feedUrlSnort: string;
    };
}> {
    return await getData('/ids-rules/status');
}

export async function getIdsRulesPreviewText(params: IdsRulesParams = {}): Promise<string> {
    const searchParams = new URLSearchParams();
    if (params.fromDate) searchParams.set('from_date', params.fromDate);
    if (params.toDate) searchParams.set('to_date', params.toDate);
    if (params.app && params.app !== 'all') searchParams.set('app', params.app);
    if (params.ruleTypes) searchParams.set('rule_types', params.ruleTypes);
    if (params.limit) searchParams.set('limit', String(params.limit));
    if (params.format) searchParams.set('format', params.format);
    const query = searchParams.toString();
    const resp = await fetch(`${API_URL}/ids-rules/preview${query ? '?' + query : ''}`, {
        cache: "no-cache",
        headers: { "API-KEY": `${getApiKey()}` },
    });
    if (!resp.ok) {
        throw new Error(`GET /ids-rules/preview failed with status ${resp.status} ${resp.statusText}`);
    }
    return await resp.text();
}