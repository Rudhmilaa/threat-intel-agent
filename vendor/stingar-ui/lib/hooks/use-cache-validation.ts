import { useState, useEffect, useCallback } from 'react';
import { validateCache, getCacheStatistics, getStaleHoneypots, validateSpecificHoneypot } from '@/lib/actions';
import { debugLog } from '@/lib/debug';

export interface CacheValidationResult {
  total_cached: number;
  fresh_count: number;
  stale_count: number;
  stale_honeypots: any[];
  freshness_percentage: number;
  validation_timestamp: string;
  max_age_hours: number;
}

export interface CacheStatistics {
  total_cached: number;
  oldest_cache_age_hours: number | null;
  newest_cache_age_hours: number | null;
  average_cache_age_hours: number | null;
  cache_timestamp: string;
}

export interface StaleHoneypotsResult {
  stale_honeypots: any[];
  count: number;
  max_age_hours: number;
  timestamp: string;
}

export interface SpecificHoneypotValidation {
  remote_id: string;
  found: boolean;
  is_stale: boolean | null;
  age_hours: number | null;
  last_updated: string | null;
  validation_timestamp: string;
}

export function useCacheValidation(maxAgeHours: number = 24) {
  const [validationResult, setValidationResult] = useState<CacheValidationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validate = useCallback(async (ageHours?: number) => {
    const hours = ageHours || maxAgeHours;
    try {
      setLoading(true);
      setError(null);
      debugLog('Validating cache with max age:', hours, 'hours');
      
      const result = await validateCache(hours);
      setValidationResult(result);
      debugLog('Cache validation result:', result);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to validate cache';
      setError(errorMessage);
      console.error('Cache validation error:', err);
    } finally {
      setLoading(false);
    }
  }, [maxAgeHours]);

  useEffect(() => {
    validate();
  }, [validate]);

  return {
    validationResult,
    loading,
    error,
    validate,
    isStale: validationResult ? validationResult.stale_count > 0 : false,
    freshnessPercentage: validationResult?.freshness_percentage || 0
  };
}

export function useCacheStatistics() {
  const [statistics, setStatistics] = useState<CacheStatistics | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchStatistics = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      debugLog('Fetching cache statistics...');
      
      const result = await getCacheStatistics();
      setStatistics(result);
      debugLog('Cache statistics:', result);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to get cache statistics';
      setError(errorMessage);
      console.error('Cache statistics error:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatistics();
  }, [fetchStatistics]);

  return {
    statistics,
    loading,
    error,
    refetch: fetchStatistics
  };
}

export function useStaleHoneypots(maxAgeHours: number = 24) {
  const [staleHoneypots, setStaleHoneypots] = useState<StaleHoneypotsResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchStaleHoneypots = useCallback(async (ageHours?: number) => {
    const hours = ageHours || maxAgeHours;
    try {
      setLoading(true);
      setError(null);
      debugLog('Fetching stale honeypots with max age:', hours, 'hours');
      
      const result = await getStaleHoneypots(hours);
      setStaleHoneypots(result);
      debugLog('Stale honeypots result:', result);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to get stale honeypots';
      setError(errorMessage);
      console.error('Stale honeypots error:', err);
    } finally {
      setLoading(false);
    }
  }, [maxAgeHours]);

  useEffect(() => {
    fetchStaleHoneypots();
  }, [fetchStaleHoneypots]);

  return {
    staleHoneypots,
    loading,
    error,
    refetch: fetchStaleHoneypots,
    staleCount: staleHoneypots?.count || 0
  };
}

export function useSpecificHoneypotValidation(remoteId: string, maxAgeHours: number = 24) {
  const [validation, setValidation] = useState<SpecificHoneypotValidation | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validate = useCallback(async (id?: string, ageHours?: number) => {
    const idToUse = id || remoteId;
    const hours = ageHours || maxAgeHours;
    
    if (!idToUse) {
      setError('Remote ID is required');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      debugLog('Validating specific honeypot:', idToUse, 'with max age:', hours, 'hours');
      
      const result = await validateSpecificHoneypot(idToUse, hours);
      setValidation(result);
      debugLog('Specific honeypot validation result:', result);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to validate honeypot';
      setError(errorMessage);
      console.error('Specific honeypot validation error:', err);
    } finally {
      setLoading(false);
    }
  }, [remoteId, maxAgeHours]);

  useEffect(() => {
    if (remoteId) {
      validate();
    }
  }, [validate, remoteId]);

  return {
    validation,
    loading,
    error,
    validate,
    isStale: validation?.is_stale || false,
    ageHours: validation?.age_hours || null
  };
}
