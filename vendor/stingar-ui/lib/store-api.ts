import {
  HoneypotStore,
  StoreResponse,
  Category,
  Tag,
  StoreStats,
  InstallationData,
  StoreFilters
} from "@/models/store";
import { HoneypotRequest, HoneypotRequestCreate } from "@/models/hp-request";
import { debugLog } from "@/lib/debug";

// Apiarist API configuration (which proxies to HP_AppStore)
const APIARIST_API_URL = process.env.API_HOST || "http://localhost:8000";
const APIARIST_API_KEY = process.env.API_KEY || "";

// Retry configuration
const RETRY_ATTEMPTS = 3;
const RETRY_DELAY = 1000; // 1 second

// Utility function for retry logic
async function retryRequest<T>(
  requestFn: () => Promise<T>,
  attempts: number = RETRY_ATTEMPTS
): Promise<T> {
  try {
    return await requestFn();
  } catch (error) {
    if (attempts > 1 && (error as any).status >= 500) {
      await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
      return retryRequest(requestFn, attempts - 1);
    }
    throw error;
  }
}

// Sanitize response data to remove sensitive information
function sanitizeResponseData(data: any): any {
  if (typeof data !== 'object' || data === null) {
    return data;
  }

  if (Array.isArray(data)) {
    return data.map(item => sanitizeResponseData(item));
  }

  const sanitized = { ...data };

  // Remove or mask sensitive fields
  const sensitiveFields = ['api_key', 'apiKey', 'token', 'password', 'secret', 'key'];
  sensitiveFields.forEach(field => {
    if (sanitized[field]) {
      sanitized[field] = '[REDACTED]';
    }
  });

  // Recursively sanitize nested objects
  Object.keys(sanitized).forEach(key => {
    if (typeof sanitized[key] === 'object' && sanitized[key] !== null) {
      sanitized[key] = sanitizeResponseData(sanitized[key]);
    }
  });

  return sanitized;
}

// Base API request function
async function makeRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${APIARIST_API_URL}${endpoint}`;
  debugLog("makeRequest: Making request to:", url);
  // Log headers without sensitive data
  const safeHeaders = { ...(options.headers as Record<string, string>) };
  if (safeHeaders['API-KEY']) {
    safeHeaders['API-KEY'] = '[REDACTED]';
  }
  debugLog("makeRequest: Options:", { method: options.method || 'GET', headers: safeHeaders });

  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "API-KEY": APIARIST_API_KEY,
      ...options.headers,
    },
  });

  debugLog("makeRequest: Response status:", response.status, response.statusText);

  if (!response.ok) {
    const errorText = await response.text();
    debugLog("makeRequest: Error response text:", errorText);
    let errorMessage = `API request failed: ${response.status} ${response.statusText}`;

    try {
      const errorData = JSON.parse(errorText);
      errorMessage = errorData.detail || errorData.message || errorMessage;
    } catch {
      // If parsing fails, use the raw error text
      errorMessage = errorText || errorMessage;
    }

    const error = new Error(errorMessage) as any;
    error.status = response.status;
    error.statusText = response.statusText;
    throw error;
  }

  const responseData = await response.json();
  // Log response data safely (avoid logging sensitive fields)
  const safeResponseData = sanitizeResponseData(responseData);
  debugLog("makeRequest: Response data:", safeResponseData);
  return responseData;
}

// Store API client
export const storeApi = {
  // Get honeypots with filtering and pagination
  async getHoneypots(
    page: number = 1,
    perPage: number = 50,
    filters?: StoreFilters
  ): Promise<StoreResponse<HoneypotStore[]>> {
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

    const endpoint = `/api/v2/store/honeypots?${params}`;
    debugLog("getHoneypots: Calling endpoint:", endpoint);

    return retryRequest(() =>
      makeRequest<{ data: HoneypotStore[], source: string }>(endpoint)
    ).then(response => {
      debugLog("getHoneypots: Response received:", response);

      // Add source information to each honeypot
      const honeypotsWithSource = response.data.map(honeypot => ({
        ...honeypot,
        dataSource: response.source as 'remote' | 'cache'
      }));

      return {
        data: honeypotsWithSource,
        pagination: undefined, // Apiarist doesn't return pagination info
        filters: filters,
        source: response.source as 'remote' | 'cache'
      };
    });
  },

  // Get specific honeypot by ID
  async getHoneypot(id: number): Promise<StoreResponse<HoneypotStore>> {
    return retryRequest(() =>
      makeRequest<{ data: HoneypotStore, source: string }>(`/api/v2/store/honeypots/${id}`)
    ).then(response => ({
      data: response.data
    }));
  },

  // Search honeypots
  async searchHoneypots(
    query: string,
    page: number = 1,
    perPage: number = 50,
    filters?: Pick<StoreFilters, 'category' | 'hpType'>
  ): Promise<StoreResponse<HoneypotStore[]>> {
    const params = new URLSearchParams({
      q: query,
      page: page.toString(),
      per_page: perPage.toString(),
    });

    if (filters) {
      if (filters.category) params.append("category", filters.category);
      if (filters.hpType) params.append("hp_type", filters.hpType);
    }

    return retryRequest(() =>
      makeRequest<{ data: HoneypotStore[], source: string }>(`/api/v2/store/search?${params}`)
    ).then(response => ({
      data: response.data,
      pagination: undefined, // Apiarist doesn't return pagination info
      filters: filters
    }));
  },

  // Install honeypot
  async installHoneypot(
    id: number,
    installationData: InstallationData
  ): Promise<{ success: boolean; installationId?: number; message?: string }> {
    return retryRequest(() =>
      makeRequest(`/api/v2/store/honeypots/${id}/install`, {
        method: "POST",
        body: JSON.stringify(installationData),
      })
    );
  },

  // Get categories
  async getCategories(): Promise<Category[]> {
    return retryRequest(() =>
      makeRequest<{ data: Category[], source: string }>(`/api/v2/store/categories`)
    ).then(response => response.data);
  },

  // Get tags
  async getTags(): Promise<Tag[]> {
    return retryRequest(() =>
      makeRequest<{ data: Tag[], source: string }>(`/api/v2/store/tags`)
    ).then(response => response.data);
  },

  // Get installed honeypots
  async getInstalledHoneypots(
    page: number = 1,
    perPage: number = 50,
    status?: string
  ): Promise<StoreResponse<HoneypotStore[]>> {
    const params = new URLSearchParams({
      page: page.toString(),
      per_page: perPage.toString(),
    });

    if (status) {
      params.append("status", status);
    }

    return retryRequest(() =>
      makeRequest<{ data: HoneypotStore[], source: string }>(`/api/v2/store/installed?${params}`)
    ).then(response => ({
      data: response.data,
      pagination: undefined // Apiarist doesn't return pagination info
    }));
  },

  // Uninstall honeypot
  async uninstallHoneypot(installationId: number): Promise<{ success: boolean; message?: string }> {
    return retryRequest(() =>
      makeRequest(`/api/v2/store/installed/${installationId}`, {
        method: "DELETE",
      })
    );
  },

  // Health check
  async healthCheck(): Promise<{ status: string; timestamp: string }> {
    return retryRequest(() =>
      makeRequest(`/api/v2/health`)
    );
  },

  // Create honeypot request
  async createRequest(
    requestData: HoneypotRequestCreate
  ): Promise<HoneypotRequest> {
    return retryRequest(() =>
      makeRequest<HoneypotRequest>(`/api/v2/store/requests`, {
        method: "POST",
        body: JSON.stringify(requestData),
      })
    );
  },

  // Get honeypot requests
  async getRequests(
    page: number = 1,
    perPage: number = 50,
    filters?: {
      status?: string;
      category?: string;
      priority?: string;
    }
  ): Promise<StoreResponse<HoneypotRequest[]>> {
    const params = new URLSearchParams({
      page: page.toString(),
      per_page: perPage.toString(),
    });

    if (filters) {
      if (filters.status) params.append("status", filters.status);
      if (filters.category) params.append("category", filters.category);
      if (filters.priority) params.append("priority", filters.priority);
    }

    return retryRequest(() =>
      makeRequest<{ data: HoneypotRequest[], source: string }>(
        `/api/v2/store/requests?${params}`
      )
    ).then(response => ({
      data: response.data || response,
      pagination: undefined,
      filters: filters
    }));
  },

  // Get specific request
  async getRequest(requestId: string): Promise<HoneypotRequest> {
    return retryRequest(() =>
      makeRequest<HoneypotRequest>(`/api/v2/store/requests/${requestId}`)
    );
  },
};

// Hook for checking if Store is available
export async function checkStoreAvailability(): Promise<boolean> {
  try {
    // Try health check first - this is more reliable
    await storeApi.healthCheck();
    return true;
  } catch (error) {
    console.warn("Store health check failed, trying categories endpoint:", error);
    try {
      // Fallback to categories endpoint
      const categories = await storeApi.getCategories();
      return true;
    } catch (categoriesError) {
      console.warn("Store is not available (both health and categories failed):", categoriesError);
      return false;
    }
  }
}

// Error types for better error handling
export class StoreApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public statusText: string,
    public endpoint?: string
  ) {
    super(message);
    this.name = "StoreApiError";
  }
}

// Enhanced error handling wrapper
export function handleStoreError(error: any): StoreApiError {
  if (error instanceof StoreApiError) {
    return error;
  }

  return new StoreApiError(
    error.message || "Unknown store API error",
    error.status || 500,
    error.statusText || "Internal Server Error"
  );
}
