"use client";

import { useState, useCallback, useEffect, useRef } from "react";
import { Button, Alert } from "@mui/material";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Download, Search, Filter, RefreshCw, BarChart3, Trash2, ArrowRight } from "lucide-react";
import { HoneypotCard } from "@/components/store/honeypot-card";
import { SearchFilters } from "@/components/store/search-filters";
import { LoadingState, ErrorState, EmptyState, StoreUnavailable, SkeletonGrid } from "@/components/store/store-states";
import {
  useHoneypots,
  useStoreAvailability,
  invalidateStoreCache
} from "@/lib/hooks/use-store";
import { StoreFilters } from "@/models/store";
import type { HoneypotStore } from "@/models/store";
import { toast } from "sonner";
import { cleanupAll } from "@/lib/client-actions";
import { useStoreCountContext } from "@/lib/hooks/use-store-count-context";
import { useCacheValidation } from "@/lib/hooks/use-cache-validation";
import { useRouter } from "next/navigation";
import { useStoreRegistration } from "@/lib/hooks/use-store-registration";

export default function HoneypotStore() {
  const [filters, setFilters] = useState<StoreFilters>({});
  const [currentPage, setCurrentPage] = useState(1);
  const [showCleanupConfirm, setShowCleanupConfirm] = useState(false);
  const router = useRouter();

  // Auto-register if needed (silent, no UI shown)
  useStoreRegistration();

  // Check store availability
  const { isAvailable, isLoading: availabilityLoading, error: availabilityError, refetch: refetchAvailability } = useStoreAvailability();

  // Get honeypots
  const {
    honeypots,
    pagination,
    isLoading,
    error,
    refetch,
    dataSource
  } = useHoneypots(currentPage, 12, filters);

  // Get store count context for refreshing count after cleanup
  const { refetch: refetchCount } = useStoreCountContext();

  // Get cache validation information
  const { validationResult, loading: cacheValidationLoading, validate: validateCache, isStale, freshnessPercentage } = useCacheValidation(24);

  // State for cleanup loading
  const [isCleaningUp, setIsCleaningUp] = useState(false);

  // State for automatic refresh on focus
  const [isRefreshing, setIsRefreshing] = useState(false);
  const lastRefreshTimeRef = useRef<number>(0);
  const lastUserActivityRef = useRef<number>(Date.now());
  const refreshDebounceTimerRef = useRef<NodeJS.Timeout | null>(null);


  // Handle filter changes
  const handleFiltersChange = useCallback((newFilters: StoreFilters) => {
    setFilters(newFilters);
    setCurrentPage(1);
  }, []);

  // Handle clear all
  const handleClearAll = useCallback(() => {
    setFilters({});
    setCurrentPage(1);
  }, []);

  // Handle refresh (silent background refresh for auto-refresh, with toast for manual)
  const handleRefresh = useCallback(async (silent: boolean = false) => {
    // Prevent concurrent refreshes
    if (isRefreshing) {
      return;
    }

    setIsRefreshing(true);
    try {
      await invalidateStoreCache();
      await refetchAvailability();
      const result = await refetch();

      // Update last refresh time
      lastRefreshTimeRef.current = Date.now();

      // Only show toast for manual refreshes
      if (!silent) {
        // Check the actual data source from the API response
        const currentDataSource = result?.source || dataSource;

        if (currentDataSource === 'remote') {
          toast.success("Store data refreshed successfully!");
        } else if (currentDataSource === 'cache') {
          toast.success("Cached data refreshed successfully!");
        } else {
          // Fallback to availability check if data source is not available
          if (isAvailable) {
            toast.success("Store data refreshed successfully!");
          } else {
            toast.success("Cached data refreshed successfully!");
          }
        }
      }
    } catch (error) {
      // Always show errors, even for silent refreshes
      if (isAvailable) {
        toast.error("Failed to refresh store data");
      } else {
        toast.error("Failed to refresh cached data");
      }
    } finally {
      setIsRefreshing(false);
    }
  }, [refetch, refetchAvailability, isAvailable, dataSource, isRefreshing]);

  // Handle honeypot installation
  const handleHoneypotInstall = useCallback((honeypot: HoneypotStore) => {
    // This will be handled by the HoneypotCard component
  }, []);

  // Handle comprehensive cleanup of invalid configurations and stale cache
  const handleCleanupInvalidConfigs = useCallback(async (skipConfirmation: boolean = false) => {
    setIsCleaningUp(true);
    try {
      const result = await cleanupAll({ max_age_days: 7, force_cleanup: false });

      // Validate result structure
      if (!result || typeof result !== 'object') {
        throw new Error("Invalid cleanup result");
      }

      const configsResult = result.configs;
      const cacheResult = result.cache;

      const configsMessage = configsResult.message || "Config cleanup completed";
      const cacheMessage = cacheResult.message || "Cache cleanup completed";
      const totalDeleted = (configsResult.deleted_count || 0) + (cacheResult.deleted_count || 0);

      // Show detailed success message (only if not auto-cleanup)
      if (!skipConfirmation) {
        if (totalDeleted > 0) {
          toast.success(
            `Cleanup completed: ${configsResult.deleted_count || 0} invalid configs and ${cacheResult.deleted_count || 0} stale cache entries removed`
          );
        } else {
          toast.success("No invalid configurations or stale cache data found");
        }
      } else if (totalDeleted > 0) {
        // Silent notification for auto-cleanup
        toast.info(`Automatically cleaned up ${totalDeleted} stale entries`);
      }

      // Refresh the store data, count, and cache validation to reflect changes
      // This ensures the sidebar badge count and cache status are updated after cleanup
      try {
        await Promise.all([
          refetch(),        // Refresh honeypot list
          refetchCount(),   // Refresh sidebar badge count
          validateCache()   // Refresh cache validation status
        ]);
      } catch (refetchError) {
        // console.warn("Failed to refresh data after cleanup:", refetchError);
        // Don't fail the cleanup if refresh fails
      }
      setShowCleanupConfirm(false);
    } catch (error: any) {
      // Only log errors in development mode
      if (process.env.NODE_ENV === 'development') {
        console.error("Error during comprehensive cleanup:", error);
      }
      if (!skipConfirmation) {
        toast.error("Failed to cleanup invalid configurations and stale cache: " + (error.message || "Unknown error"));
      }
    } finally {
      setIsCleaningUp(false);
    }
  }, [refetch, refetchCount, validateCache]);

  // Optional: Automatic cleanup for high stale data thresholds
  useEffect(() => {
    // Auto-cleanup when stale data exceeds 50% or more than 50 stale items
    if (
      isAvailable &&
      validationResult &&
      !isCleaningUp &&
      (freshnessPercentage < 50 || validationResult.stale_count > 50)
    ) {
      // Only auto-cleanup once per session to avoid repeated prompts
      const autoCleanupKey = 'hp-store-auto-cleanup-done';
      if (!sessionStorage.getItem(autoCleanupKey)) {
        sessionStorage.setItem(autoCleanupKey, 'true');
        // Auto-cleanup silently in background (skip confirmation dialog)
        handleCleanupInvalidConfigs(true).catch(() => {
          // Silently fail - user can manually trigger if needed
        });
      }
    }
  }, [isAvailable, validationResult, freshnessPercentage, isCleaningUp, handleCleanupInvalidConfigs]);

  // Track user activity for idle detection
  useEffect(() => {
    const updateActivity = () => {
      lastUserActivityRef.current = Date.now();
    };

    const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'];
    events.forEach(event => {
      window.addEventListener(event, updateActivity, { passive: true });
    });

    return () => {
      events.forEach(event => {
        window.removeEventListener(event, updateActivity);
      });
    };
  }, []);

  // Automatic refresh on window focus with all safeguards
  useEffect(() => {
    const handleFocus = () => {
      // Clear any existing debounce timer
      if (refreshDebounceTimerRef.current) {
        clearTimeout(refreshDebounceTimerRef.current);
      }

      // Debounce focus event (500ms)
      refreshDebounceTimerRef.current = setTimeout(() => {
        const now = Date.now();
        const MIN_REFRESH_INTERVAL = 5 * 60 * 1000; // 5 minutes
        const IDLE_THRESHOLD = 30 * 1000; // 30 seconds
        const FRESHNESS_THRESHOLD = 80; // 80%

        // Check 1: Minimum refresh interval (5 minutes)
        const timeSinceLastRefresh = now - lastRefreshTimeRef.current;
        if (timeSinceLastRefresh < MIN_REFRESH_INTERVAL) {
          return; // Too soon since last refresh
        }

        // Check 2: Store availability
        if (!isAvailable) {
          return; // Store is not available
        }

        // Check 3: Cache validation must be complete
        if (cacheValidationLoading || !validationResult) {
          return; // Cache validation not ready
        }

        // Check 4: Staleness check (cache >24h or freshness < 80%)
        const isCacheStale = validationResult.stale_count > 0;
        const isFreshnessLow = validationResult.freshness_percentage < FRESHNESS_THRESHOLD;
        // Also check if cache age exceeds threshold (if we can determine it)
        // For now, we'll use stale_count and freshness_percentage as indicators
        if (!isCacheStale && !isFreshnessLow) {
          return; // Cache is fresh, no need to refresh
        }

        // Check 5: User idle check (user idle >30 seconds)
        const timeSinceLastActivity = now - lastUserActivityRef.current;
        if (timeSinceLastActivity < IDLE_THRESHOLD) {
          return; // User is active, don't refresh
        }

        // Check 6: In-flight protection (prevent concurrent refreshes)
        if (isRefreshing) {
          return; // Refresh already in progress
        }

        // All checks passed - perform silent background refresh
        handleRefresh(true).catch(() => {
          // Errors are already handled in handleRefresh
        });
      }, 500); // 500ms debounce
    };

    const handleVisibilityChange = () => {
      // Also trigger on visibility change (when tab becomes visible)
      if (document.visibilityState === 'visible') {
        handleFocus();
      }
    };

    window.addEventListener('focus', handleFocus);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      window.removeEventListener('focus', handleFocus);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      if (refreshDebounceTimerRef.current) {
        clearTimeout(refreshDebounceTimerRef.current);
      }
    };
  }, [isAvailable, cacheValidationLoading, validationResult, isRefreshing, handleRefresh]);

  // Handle cleanup confirmation
  const handleCleanupClick = useCallback(() => {
    setShowCleanupConfirm(true);
  }, []);

  // Temporarily disable availability check to debug
  // If store availability is still loading, show loading state
  if (availabilityLoading) {
    return (
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold">Honeypot Store</h1>
            <p className="text-muted-foreground">
              Browse, download and request new honeypots from the STINGAR Team
            </p>
          </div>
        </div>

        <LoadingState message="Checking store availability..." />
      </div>
    );
  }

  // Temporarily disable availability check to debug
  // If store is not available, show unavailable state
  if (!isAvailable) {
    // return (
    //   <div className="space-y-6">
    //     {/* Header */}
    //     <div className="flex items-center justify-between">
    //       <div className="flex items-center space-x-4">
    //         <Link href="/deploy">
    //           <Button variant="outline" size="sm">
    //             <ArrowLeft className="h-4 w-4 mr-2" />
    //             Back to Deploy
    //           </Button>
    //         </Link>
    //         <div>
    //           <h1 className="text-2xl font-bold">Honeypot Store</h1>
    //           <p className="text-muted-foreground">
    //             Browse and download honeypot configurations from the STINGAR Honeypot Store
    //           </p>
    //         </div>
    //       </div>
    //     </div>

    //     <StoreUnavailable onRetry={refetchAvailability} />
    //   </div>
    // );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold">Honeypot Store</h2>
          <p className="text-muted-foreground">
            Browse, download and request new honeypots from the STINGAR Team
          </p>
        </div>
        <Button
          onClick={() => router.push('/hp-store/requests')}
          variant="outlined"
          color="primary"
          size="small"
          endIcon={<ArrowRight className="h-4 w-4" />}
        >
          Request New Honeypot
        </Button>
      </div>

      {/* Cache Status Indicator - Only shown for warnings and errors */}
      {validationResult && (isStale || !isAvailable || dataSource === 'cache') && (
        <div className={`p-3 rounded-lg border ${(dataSource === 'cache' || !isAvailable)
          ? 'bg-orange-50 border-orange-200 text-orange-800'
          : 'bg-yellow-50 border-yellow-200 text-yellow-800'
          }`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <div className={`w-2 h-2 rounded-full ${(dataSource === 'cache' || !isAvailable)
                ? 'bg-orange-500'
                : 'bg-yellow-500'
                }`} />
              <span className="text-sm font-medium">
                {(dataSource === 'cache' || !isAvailable)
                  ? 'Store Unavailable - Showing Cached Data'
                  : 'Cache Status: Contains Stale Data'
                }
              </span>
            </div>
            <div className="flex items-center space-x-3">
              <div className="text-sm">
                {validationResult.fresh_count} fresh, {validationResult.stale_count} stale
                ({freshnessPercentage}% fresh)
              </div>
              {isAvailable && isStale && validationResult.stale_count > 0 && (
                <Button
                  onClick={handleCleanupClick}
                  variant="outlined"
                  color="error"
                  size="small"
                  disabled={isCleaningUp}
                  startIcon={isCleaningUp ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Trash2 className="h-3 w-3" />}
                  sx={{
                    minWidth: 'auto',
                    padding: '4px 12px',
                    fontSize: '0.75rem',
                    textTransform: 'none'
                  }}
                >
                  {isCleaningUp ? 'Cleaning...' : 'Cleanup'}
                </Button>
              )}
            </div>
          </div>
          {(dataSource === 'cache' || !isAvailable) && (
            <div className="mt-2 text-xs text-orange-700">
              The remote honeypot store is currently unavailable. You are viewing cached data which may be outdated.
            </div>
          )}
          {isAvailable && isStale && (
            <div className="mt-2 text-xs text-yellow-700">
              Some cached honeypot data is older than 24 hours. Click Cleanup to remove stale entries.
            </div>
          )}
        </div>
      )}

      {/* Feature Description Banner */}
      <Alert severity="info" sx={{ mb: 3 }}>
        This new feature allows downloading new Honeypots recently developed by the STINGAR team or requesting new Honeypots to be developed.
        This is a free service currently under beta trial.
        Click to install a new Honeypot Configuration into the library, then deploy it from the &apos;Deploy Honeypot&apos; page.
      </Alert>

      {/* Content */}
      <div className="space-y-6">
        {/* Loading State */}
        {isLoading && <SkeletonGrid count={6} />}

        {/* Error State */}
        {error && (
          <ErrorState
            error={error}
            onRetry={refetch}
            title="Failed to load honeypots"
          />
        )}

        {/* Empty State */}
        {!isLoading && !error && honeypots.length === 0 && (
          <EmptyState
            title="No honeypots available"
            description="The store is currently empty. Check back later for new honeypot configurations."
            showFilters={Object.keys(filters).length > 0}
            onClearFilters={handleClearAll}
          />
        )}

        {/* Combined Honeypots and Requests Grid */}
        {!isLoading && !error && (
          <>
            {/* Available Honeypots Section */}
            {honeypots.length > 0 && (
              <>
                <div className="mb-6">
                  <h3 className="text-lg font-semibold mb-2">Available Honeypots</h3>
                  <p className="text-sm text-muted-foreground">Ready to download and install</p>
                </div>

                {/* Filter Bar - Moved below header */}
                <div className="mb-6">
                  <SearchFilters
                    filters={filters}
                    onFiltersChange={handleFiltersChange}
                    onClearAll={handleClearAll}
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
                  {honeypots.map((honeypot: HoneypotStore) => (
                    <HoneypotCard
                      key={honeypot.id}
                      honeypot={honeypot}
                      onInstall={handleHoneypotInstall}
                    />
                  ))}
                </div>
              </>
            )}


            {/* Pagination - Disabled since apiarist doesn't return pagination info */}
            {/* {pagination && pagination.pages > 1 && (
              <div className="flex items-center justify-center space-x-2">
                <Button
                  variant="outline"
                  onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
                  disabled={currentPage === 1}
                >
                  Previous
                </Button>
                <span className="text-sm text-muted-foreground">
                  Page {currentPage} of {pagination.pages}
                </span>
                <Button
                  variant="outline"
                  onClick={() => setCurrentPage(Math.min(pagination.pages, currentPage + 1))}
                  disabled={currentPage === pagination.pages}
                >
                  Next
                </Button>
              </div>
            )} */}
          </>
        )}
      </div>

      {/* Integration Status - Show only when store is available but no honeypots */}
      {isAvailable && !isLoading && !error && honeypots.length === 0 && Object.keys(filters).length === 0 && (
        <Card className="bg-blue-50 border-blue-200">
          <CardHeader>
            <CardTitle className="text-blue-900">HP Store Integration</CardTitle>
            <CardDescription className="text-blue-700">
              The STINGAR Honeypot Store is connected and ready. Honeypot configurations will appear here once they are added to the store.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 text-sm text-blue-800">
              <p>• Browse honeypot configurations from the centralized store</p>
              <p>• Download and deploy configurations directly to your STINGAR environment</p>
              <p>• Rate and review honeypot configurations</p>
              <p>• Submit your own honeypot configurations to the community</p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Cleanup Confirmation Dialog */}
      {showCleanupConfirm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-red-600 mb-4">Confirm Comprehensive Cleanup</h3>
            <p className="text-gray-700 mb-6">
              This will permanently delete:
              <br />• Invalid configurations with empty or invalid honeypot types
              <br />• Stale cached honeypot data older than 7 days
              <br />
              <br />This action cannot be undone.
            </p>
            <div className="flex justify-end space-x-3">
              <Button
                variant="outlined"
                onClick={() => setShowCleanupConfirm(false)}
                size="small"
              >
                Cancel
              </Button>
              <Button
                variant="contained"
                color="error"
                onClick={() => handleCleanupInvalidConfigs(false)}
                size="small"
                disabled={isCleaningUp}
              >
                {isCleaningUp ? 'Cleaning...' : 'Cleanup All'}
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
