"use client";

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

interface StoreCountContextType {
  count: number | null;
  loading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

const StoreCountContext = createContext<StoreCountContextType | undefined>(undefined);

export function StoreCountProvider({ children }: { children: React.ReactNode }) {
  const [count, setCount] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchCount = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      // Use API route instead of server action to avoid hash mismatch errors
      const response = await fetch('/api/store/honeypots/count', {
        cache: 'no-cache',
      });
      
      if (!response.ok) {
        // Silently fail for 401 (auth not configured) - don't show error
        if (response.status === 401) {
          setError(null);
          return;
        }
        throw new Error(`Failed to fetch store count: ${response.statusText}`);
      }
      
      const data = await response.json();
      setCount(data.data.count);
    } catch (err) {
      // Only log non-401 errors
      if (err instanceof Error && !err.message.includes('401')) {
        console.error('Failed to fetch store count:', err);
      }
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch count';
      setError(errorMessage);
      // Don't clear count on error - keep previous value if available
      // This prevents flickering when there's a temporary error
    } finally {
      setLoading(false);
    }
  }, []);

  // Fetch count on mount
  useEffect(() => {
    fetchCount();
  }, [fetchCount]);

  const value: StoreCountContextType = {
    count,
    loading,
    error,
    refetch: fetchCount,
  };

  return (
    <StoreCountContext.Provider value={value}>
      {children}
    </StoreCountContext.Provider>
  );
}

export function useStoreCountContext() {
  const context = useContext(StoreCountContext);
  if (context === undefined) {
    throw new Error('useStoreCountContext must be used within a StoreCountProvider');
  }
  return context;
}
