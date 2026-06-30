import useSWR, { SWRConfiguration, mutate } from 'swr';
import { HoneypotStore, StoreFilters, Category, Tag, StoreStats } from '@/models/store';

// Client-side API functions
const storeApi = {
  getHoneypots: async (page: number = 1, perPage: number = 50, filters?: any) => {
    const params = new URLSearchParams({
      page: page.toString(),
      perPage: perPage.toString(),
    });

    if (filters) {
      if (filters.category) params.append("category", filters.category);
      if (filters.hpType) params.append("hpType", filters.hpType);
      if (filters.status) params.append("status", filters.status);
      if (filters.tags) params.append("tags", filters.tags);
      if (filters.minRating) params.append("minRating", filters.minRating.toString());
    }

    try {
      const response = await fetch(`/api/store/honeypots?${params}`);
      if (!response.ok) {
        throw new Error(`Failed to fetch honeypot data - are you connected to the Internet?`);
      }
      return response.json();
    } catch (fetchError) {
      // Handle network errors (e.g., no internet connection)
      if (fetchError instanceof TypeError && fetchError.message.includes('fetch')) {
        throw new Error(`Failed to fetch honeypot data - are you connected to the Internet?`);
      }
      throw fetchError;
    }
  },

  getCategories: async () => {
    const response = await fetch('/api/store/categories');
    if (!response.ok) {
      throw new Error(`Failed to fetch categories: ${response.statusText}`);
    }
    return response.json();
  },

  checkAvailability: async () => {
    const response = await fetch('/api/store/availability');
    if (!response.ok) {
      throw new Error(`Failed to check availability: ${response.statusText}`);
    }
    return response.json();
  }
};

// SWR configuration for store data
const storeSWRConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  revalidateOnReconnect: true,
  dedupingInterval: 5000, // 5 seconds - deduplicate in-flight requests within this window (handles React Strict Mode double renders)
  errorRetryCount: 3,
  errorRetryInterval: 5000,
  keepPreviousData: true, // Keep previous data while revalidating to prevent flicker
};

// Hook for checking if Store is available
export function useStoreAvailability() {
  const { data, error, mutate, isLoading } = useSWR(
    'store/availability',
    async () => {
      const result = await storeApi.checkAvailability();
      return result.isAvailable;
    },
    {
      ...storeSWRConfig,
      refreshInterval: 600000, // Check every 10 minutes
    }
  );

  return {
    isAvailable: data ?? false,
    isLoading: !error && data === undefined,
    error: error || null,
    refetch: mutate,
  };
}

// Hook for checking if Store is enabled (REMOTE_STORE_ENABLED flag)
export function useStoreEnabled() {
  const { data, error, mutate, isLoading } = useSWR(
    'store/enabled',
    async () => {
      const response = await fetch('/api/store/config');
      if (!response.ok) {
        const errorText = await response.text();
        // Create error object with status for retry logic
        const error: any = new Error(`Failed to fetch store config: ${response.status}`);
        error.status = response.status;
        error.statusText = response.statusText;
        error.details = errorText;
        throw error; // Throw error so SWR can retry
      }
      const config = await response.json();
      // Check REMOTE_STORE_ENABLED flag (handle various field name formats)
      // API returns uppercase REMOTE_STORE_ENABLED, check that first
      const enabled = config.REMOTE_STORE_ENABLED ||
        config.remote_store_enabled ||
        config.remoteStoreEnabled ||
        config.enabled;
      // Handle string 'true', 'false', '1', '0' and boolean true/false
      const isEnabled = enabled === true ||
        (typeof enabled === 'string' && enabled.toLowerCase() === 'true') ||
        enabled === '1' ||
        enabled === 1;
      return isEnabled;
    },
    {
      ...storeSWRConfig,
      refreshInterval: 600000, // Check every 10 minutes
      // Retry on errors, including 401 (might be transient startup issue)
      // SWR will retry up to errorRetryCount times with errorRetryInterval delay
      shouldRetryOnError: (error) => {
        // Retry on all errors - 401 might be transient if Apiarist isn't ready yet
        // The hook defaults to false anyway, so retrying won't hurt
        return true;
      },
      // Custom retry logic with longer delays for 401 errors (Apiarist startup)
      onErrorRetry: (error, key, config, revalidate, { retryCount }) => {
        // Don't retry indefinitely
        if (retryCount >= (config.errorRetryCount || 3)) {
          return;
        }
        // For 401 errors, wait longer (Apiarist might be starting up)
        // Use exponential backoff: 2s, 4s, 8s for 401 errors
        const baseDelay = config.errorRetryInterval || 5000;
        const waitTime = error?.status === 401
          ? Math.min(baseDelay * Math.pow(2, retryCount), 10000)  // Cap at 10s
          : baseDelay;
        setTimeout(() => revalidate({ retryCount }), waitTime);
      },
    }
  );

  return {
    isEnabled: data ?? false,
    isLoading: !error && data === undefined,
    error: error || null,
    refetch: mutate,
  };
}

// Hook for getting honeypots with filtering and pagination
export function useHoneypots(
  page: number = 1,
  perPage: number = 50,
  filters?: StoreFilters
) {
  const filterKey = filters ? JSON.stringify(filters) : 'no-filters';
  const key = `store/honeypots/${page}/${perPage}/${filterKey}`;

  const { data, error, mutate, isLoading } = useSWR(
    key,
    async () => {
      try {
        return await storeApi.getHoneypots(page, perPage, filters);
      } catch (apiError) {
        console.error("useHoneypots: API call failed:", apiError);
        throw apiError;
      }
    },
    storeSWRConfig
  );

  return {
    honeypots: data?.data ?? [],
    pagination: undefined, // Apiarist doesn't return pagination info
    filters: filters,
    isLoading,
    error: error || null,
    refetch: mutate,
    dataSource: data?.source, // Include data source information
  };
}

// Hook for getting categories
export function useCategories() {
  const { data, error, mutate, isLoading } = useSWR(
    'store/categories',
    async () => {
      const result = await storeApi.getCategories();
      return result;
    },
    {
      ...storeSWRConfig,
      refreshInterval: 600000, // Refresh every 10 minutes
    }
  );

  return {
    categories: data?.data ?? [],
    isLoading,
    error: error || null,
    refetch: mutate,
  };
}

// Hook for getting tags
export function useTags() {
  const { data, error, mutate, isLoading } = useSWR(
    'store/tags',
    async () => {
      const response = await fetch('/api/store/tags');
      if (!response.ok) {
        throw new Error(`Failed to fetch tags: ${response.statusText}`);
      }
      return response.json();
    },
    {
      ...storeSWRConfig,
      refreshInterval: 600000, // Refresh every 10 minutes
    }
  );

  return {
    tags: data?.data ?? [],
    isLoading,
    error: error || null,
    refetch: mutate,
  };
}

// Hook for installing a honeypot
export function useInstallHoneypot() {
  const installHoneypot = async (honeypotId: number, installationData: any) => {
    try {
      const response = await fetch('/api/store/install', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ honeypotId, installationData }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Installation failed');
      }

      const result = await response.json();
      return result;
    } catch (error) {
      console.error('Installation failed:', error);
      throw error;
    }
  };

  return { installHoneypot };
}

// Utility function to invalidate store cache
export function invalidateStoreCache() {
  mutate('store/honeypots');
  mutate('store/categories');
  mutate('store/availability');
}
