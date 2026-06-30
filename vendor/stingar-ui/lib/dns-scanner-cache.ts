/**
 * Local storage cache utilities for DNS Vulnerability Scanner
 * Provides offline functionality by persisting scan results and description
 */

const CACHE_KEYS = {
    SCANS: 'dns_scanner_scans',
    RESULTS: (scanId: number) => `dns_scanner_results_${scanId}`,
    DESCRIPTION: 'dns_scanner_description',
    CACHE_TIMESTAMP: 'dns_scanner_cache_timestamp',
} as const;

const CACHE_EXPIRY_HOURS = 24;

export interface CachedScan {
    id: number;
    domain: string;
    status: string;
    requested_at: string;
    completed_at?: string;
    cached_at: string;
}

export interface CachedResult {
    id: number;
    scan_id: number;
    url: string;
    vulnerability_type: string;
    severity: string;
    description: string;
    cve_id?: string;
    is_fixed: boolean;
    notes?: string;
    cached_at: string;
}

/**
 * Check if cache is available and not expired
 */
export function isCacheValid(): boolean {
    if (typeof window === 'undefined') return false;

    const timestamp = localStorage.getItem(CACHE_KEYS.CACHE_TIMESTAMP);
    if (!timestamp) return false;

    const cacheTime = new Date(timestamp).getTime();
    const now = Date.now();
    const expiryMs = CACHE_EXPIRY_HOURS * 60 * 60 * 1000;

    return (now - cacheTime) < expiryMs;
}

/**
 * Get cached scans list
 */
export function getCachedScans(): CachedScan[] {
    if (typeof window === 'undefined') return [];

    try {
        const cached = localStorage.getItem(CACHE_KEYS.SCANS);
        if (!cached) return [];

        return JSON.parse(cached);
    } catch (error) {
        // Only log in development
        if (process.env.NODE_ENV === 'development') {
            console.error('Error reading cached scans:', error);
        }
        return [];
    }
}

/**
 * Save scans to cache
 */
export function saveScansToCache(scans: any[]): void {
    if (typeof window === 'undefined') return;

    try {
        const cachedScans: CachedScan[] = scans.map(scan => ({
            ...scan,
            cached_at: new Date().toISOString(),
        }));

        localStorage.setItem(CACHE_KEYS.SCANS, JSON.stringify(cachedScans));
        localStorage.setItem(CACHE_KEYS.CACHE_TIMESTAMP, new Date().toISOString());
    } catch (error) {
        // Only log in development
        if (process.env.NODE_ENV === 'development') {
            console.error('Error saving scans to cache:', error);
        }
    }
}

/**
 * Get cached results for a specific scan
 */
export function getCachedResults(scanId: number): CachedResult[] {
    if (typeof window === 'undefined') return [];

    try {
        const cached = localStorage.getItem(CACHE_KEYS.RESULTS(scanId));
        if (!cached) return [];

        return JSON.parse(cached);
    } catch (error) {
        // Only log in development
        if (process.env.NODE_ENV === 'development') {
            console.error('Error reading cached results:', error);
        }
        return [];
    }
}

/**
 * Save scan results to cache
 */
export function saveResultsToCache(scanId: number, results: any[]): void {
    if (typeof window === 'undefined') return;

    try {
        const cachedResults: CachedResult[] = results.map(result => ({
            ...result,
            cached_at: new Date().toISOString(),
        }));

        localStorage.setItem(CACHE_KEYS.RESULTS(scanId), JSON.stringify(cachedResults));
        localStorage.setItem(CACHE_KEYS.CACHE_TIMESTAMP, new Date().toISOString());
    } catch (error) {
        // Only log in development
        if (process.env.NODE_ENV === 'development') {
            console.error('Error saving results to cache:', error);
        }
    }
}

/**
 * Get cached description string
 */
export function getCachedDescription(): string | null {
    if (typeof window === 'undefined') return null;

    try {
        return localStorage.getItem(CACHE_KEYS.DESCRIPTION);
    } catch (error) {
        // Only log in development
        if (process.env.NODE_ENV === 'development') {
            console.error('Error reading cached description:', error);
        }
        return null;
    }
}

/**
 * Save description string to cache
 */
export function saveDescriptionToCache(description: string): void {
    if (typeof window === 'undefined') return;

    try {
        localStorage.setItem(CACHE_KEYS.DESCRIPTION, description);
        localStorage.setItem(CACHE_KEYS.CACHE_TIMESTAMP, new Date().toISOString());
    } catch (error) {
        // Only log in development
        if (process.env.NODE_ENV === 'development') {
            console.error('Error saving description to cache:', error);
        }
    }
}

/**
 * Add or update a scan in cache
 */
export function updateScanInCache(scan: any): void {
    if (typeof window === 'undefined') return;

    try {
        const scans = getCachedScans();
        const existingIndex = scans.findIndex(s => s.id === scan.id);

        const cachedScan: CachedScan = {
            ...scan,
            cached_at: new Date().toISOString(),
        };

        if (existingIndex >= 0) {
            scans[existingIndex] = cachedScan;
        } else {
            scans.unshift(cachedScan); // Add to beginning
        }

        // Keep only last 50 scans
        const limitedScans = scans.slice(0, 50);
        localStorage.setItem(CACHE_KEYS.SCANS, JSON.stringify(limitedScans));
        localStorage.setItem(CACHE_KEYS.CACHE_TIMESTAMP, new Date().toISOString());
    } catch (error) {
        // Only log in development
        if (process.env.NODE_ENV === 'development') {
            console.error('Error updating scan in cache:', error);
        }
    }
}

/**
 * Update a result in cache
 */
export function updateResultInCache(scanId: number, result: any): void {
    if (typeof window === 'undefined') return;

    try {
        const results = getCachedResults(scanId);
        const existingIndex = results.findIndex(r => r.id === result.id);

        const cachedResult: CachedResult = {
            ...result,
            cached_at: new Date().toISOString(),
        };

        if (existingIndex >= 0) {
            results[existingIndex] = cachedResult;
        } else {
            results.push(cachedResult);
        }

        localStorage.setItem(CACHE_KEYS.RESULTS(scanId), JSON.stringify(results));
        localStorage.setItem(CACHE_KEYS.CACHE_TIMESTAMP, new Date().toISOString());
    } catch (error) {
        // Only log in development
        if (process.env.NODE_ENV === 'development') {
            console.error('Error updating result in cache:', error);
        }
    }
}

/**
 * Clear all DNS scanner cache
 */
export function clearDNSScannerCache(): void {
    if (typeof window === 'undefined') return;

    try {
        // Clear scans
        localStorage.removeItem(CACHE_KEYS.SCANS);

        // Clear all result caches (we need to iterate through keys)
        const keysToRemove: string[] = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith('dns_scanner_results_')) {
                keysToRemove.push(key);
            }
        }
        keysToRemove.forEach(key => localStorage.removeItem(key));

        // Clear description
        localStorage.removeItem(CACHE_KEYS.DESCRIPTION);

        // Clear timestamp
        localStorage.removeItem(CACHE_KEYS.CACHE_TIMESTAMP);
    } catch (error) {
        // Only log in development
        if (process.env.NODE_ENV === 'development') {
            console.error('Error clearing DNS scanner cache:', error);
        }
    }
}

