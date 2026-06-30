"use client";

import { useState, useEffect, useRef } from "react";
import { Button, TextField, Box, Alert, CircularProgress, Chip } from "@mui/material";
import DNSScannerResultsTable from "@/components/dns-scanner/dns-scanner-results-table";
import { toast } from "sonner";
import {
  getCachedScans,
  getCachedDescription,
  saveScansToCache,
  saveDescriptionToCache,
  updateScanInCache,
  isCacheValid,
  getCachedResults,
  saveResultsToCache,
} from "@/lib/dns-scanner-cache";

interface ScanRequest {
  domain: string;
  user_identifier: string;
}

interface VulnerabilityScan {
  id: number;
  domain: string;
  status: string;
  requested_at: string;
  completed_at?: string;
  results?: VulnerabilityResult[];
}

interface VulnerabilityResult {
  id: number;
  url: string;
  vulnerability_type: string;
  severity: string;
  description: string;
  cve_id?: string;
  is_fixed: boolean;
  is_resolved?: boolean;  // Whether the DNS alert is resolved
  notes?: string;
}

export default function DNSVulnerabilityScanner() {
  const [domain, setDomain] = useState("");
  const [loading, setLoading] = useState(false);
  const [scans, setScans] = useState<VulnerabilityScan[]>([]);
  const [selectedScan, setSelectedScan] = useState<VulnerabilityScan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [description, setDescription] = useState<string>("Enter a domain name to scan for known vulnerabilities. This tool helps identify potential security issues associated with your domain.");
  const [loadingDescription, setLoadingDescription] = useState(true);
  const [usingCache, setUsingCache] = useState(false);
  const [cacheStale, setCacheStale] = useState(false);
  const recentlyCompletedScanId = useRef<number | null>(null);

  // Default description to use if API and cache are both unavailable
  const DEFAULT_DESCRIPTION = "Enter a domain name to scan for known vulnerabilities. This tool helps identify potential security issues associated with your domain.";

  const validateDomain = (domain: string): { valid: boolean; error?: string } => {
    const trimmed = domain.trim();

    if (!trimmed) {
      return { valid: false, error: "Please enter a domain name" };
    }

    // Check if domain ends with .edu
    if (!trimmed.toLowerCase().endsWith(".edu")) {
      return { valid: false, error: "Domain must be a .edu domain" };
    }

    // Basic domain format validation
    // Domain should contain only letters, numbers, dots, and hyphens
    // Should not start or end with a dot or hyphen
    // Should have at least one dot (for subdomain.domain.edu format)
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+edu$/i;

    if (!domainRegex.test(trimmed)) {
      return { valid: false, error: "Invalid domain format. Domain must be a valid .edu domain (e.g., example.edu or subdomain.example.edu)" };
    }

    // Additional checks
    if (trimmed.length > 253) {
      return { valid: false, error: "Domain name is too long (maximum 253 characters)" };
    }

    if (trimmed.includes("..")) {
      return { valid: false, error: "Domain cannot contain consecutive dots" };
    }

    return { valid: true };
  };

  const handleScan = async () => {
    const validation = validateDomain(domain);
    if (!validation.valid) {
      toast.error(validation.error || "Invalid domain");
      setError(validation.error || "Invalid domain");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const userIdentifier = "admin"; // TODO: Get from auth context

      const response = await fetch("/api/dns-scanner/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          domain: domain.trim(),
          user_identifier: userIdentifier,
        }),
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        // Check if it's a service unavailable error (503)
        if (response.status === 503) {
          throw new Error("HP App Store is currently unavailable. Please try again later.");
        }
        throw new Error(errorData.detail || "Failed to start scan");
      }

      const scan = await response.json();
      const updatedScans = [scan, ...scans];
      setScans(updatedScans);

      // Update cache
      updateScanInCache(scan);

      toast.success("Scan started successfully");

      // Poll for completion
      pollScanStatus(scan.id);

    } catch (err: any) {
      setError(err.message);
      toast.error(err.message);
    } finally {
      setLoading(false);
    }
  };

  const pollScanStatus = async (scanId: number) => {
    const maxAttempts = 120; // 2 minutes max (120 * 1s = 2 minutes)
    const maxErrorAttempts = 5; // Stop after 5 consecutive errors
    let attempts = 0;
    let consecutiveErrors = 0;

    // Poll immediately, then continue with interval
    const poll = async () => {
      attempts++;

      try {
        const response = await fetch(`/api/dns-scanner/scans/${scanId}`);

        if (response.ok) {
          // Reset error counter on success
          consecutiveErrors = 0;

          const scan = await response.json();

          if (scan.status === "completed" || scan.status === "failed") {
            // Update cache
            updateScanInCache(scan);

            if (scan.status === "completed") {
              // Mark this scan as recently completed to prevent useEffect from overriding it
              recentlyCompletedScanId.current = scanId;
              // Load full scan details with results to ensure they're available
              await loadScanDetails(scanId);
              // Clear the ref after a short delay
              setTimeout(() => {
                recentlyCompletedScanId.current = null;
              }, 1000);
            }

            // Refresh scans list (this will trigger the useEffect to check for newer scans)
            fetchScans();
            return true; // Signal to stop polling
          }
        } else {
          // Handle error status codes
          consecutiveErrors++;

          // Check if it's a service unavailable error (503)
          if (response.status === 503) {
            // HP App Store is unavailable - try to use cache and stop polling
            const cachedResults = getCachedResults(scanId);
            const cachedScans = getCachedScans();
            const cachedScan = cachedScans.find(s => s.id === scanId);

            if (cachedScan) {
              // Update with cached data
              setSelectedScan({
                ...cachedScan,
                results: cachedResults.length > 0 ? cachedResults : [],
              });
              setUsingCache(true);
              toast.warning("HP App Store unavailable. Showing cached scan data if available.");
            } else {
              toast.warning("HP App Store unavailable. Unable to retrieve scan status.");
            }
            return true; // Stop polling
          }

          // Check if scan not found (404)
          if (response.status === 404) {
            toast.error("Scan not found. It may have been deleted.");
            return true; // Stop polling
          }

          // For 500 errors, try a few times then give up
          if (response.status === 500 && consecutiveErrors >= maxErrorAttempts) {
            const errorData = await response.json().catch(() => ({}));
            toast.error(`Failed to retrieve scan status after ${maxErrorAttempts} attempts. ${errorData.detail || "Please refresh the page."}`);

            // Try to use cache as fallback
            const cachedResults = getCachedResults(scanId);
            const cachedScans = getCachedScans();
            const cachedScan = cachedScans.find(s => s.id === scanId);

            if (cachedScan) {
              setSelectedScan({
                ...cachedScan,
                results: cachedResults.length > 0 ? cachedResults : [],
              });
              setUsingCache(true);
            }

            return true; // Stop polling
          }

          // For other errors, log but continue (up to max attempts)
          if (process.env.NODE_ENV === "development") {
            const errorData = await response.json().catch(() => ({}));
            console.warn(`Polling error (attempt ${attempts}/${maxAttempts}):`, response.status, errorData);
          }
        }
      } catch (err) {
        // Network errors
        consecutiveErrors++;

        // Only log in development
        if (process.env.NODE_ENV === "development") {
          console.error("Error polling scan status:", err);
        }

        // Stop after too many consecutive errors
        if (consecutiveErrors >= maxErrorAttempts) {
          toast.error(`Network error while polling scan status. Stopped after ${maxErrorAttempts} attempts.`);

          // Try to use cache as fallback
          const cachedResults = getCachedResults(scanId);
          const cachedScans = getCachedScans();
          const cachedScan = cachedScans.find(s => s.id === scanId);

          if (cachedScan) {
            setSelectedScan({
              ...cachedScan,
              results: cachedResults.length > 0 ? cachedResults : [],
            });
            setUsingCache(true);
          }

          return true; // Stop polling
        }
      }

      if (attempts >= maxAttempts) {
        toast.warning("Scan status polling timed out. The scan may still be in progress.");
        return true; // Signal to stop polling
      }
      return false; // Continue polling
    };

    // Poll immediately
    const shouldStop = await poll();
    if (shouldStop) return;

    // Then continue with interval
    const interval = setInterval(async () => {
      const shouldStop = await poll();
      if (shouldStop) {
        clearInterval(interval);
      }
    }, 1000); // Poll every 1 second for faster updates
  };

  const fetchScans = async () => {
    try {
      const response = await fetch("/api/dns-scanner/scans");
      if (response.ok) {
        const data = await response.json();
        setScans(data);
        saveScansToCache(data);
        setUsingCache(false);
        setCacheStale(false);
      } else {
        // Check if it's a service unavailable error (503)
        if (response.status === 503) {
          // API failed with 503, try cache
          throw new Error("Service unavailable");
        }
        // API failed, try cache
        throw new Error("API unavailable");
      }
    } catch (err) {
      // Only log in development
      if (process.env.NODE_ENV === "development") {
        console.error("Error fetching scans:", err);
      }

      // Fall back to cache
      const cachedScans = getCachedScans();
      if (cachedScans.length > 0) {
        setScans(cachedScans);
        setUsingCache(true);
        setCacheStale(!isCacheValid());
        toast.info("HP App Store is currently unavailable. Showing cached scan data.");
      } else {
        // No cache available - show message to user
        setScans([]);
        setUsingCache(false);
        toast.warning("HP App Store is currently unavailable and no cached data is available.");
      }
    }
  };

  const fetchDescription = async () => {
    try {
      const response = await fetch("/api/dns-scanner/config/description");
      if (response.ok) {
        const data = await response.json();
        const desc = data.description || DEFAULT_DESCRIPTION;
        setDescription(desc);
        saveDescriptionToCache(desc);
        setUsingCache(false);
      } else {
        // API failed, try cache
        throw new Error("API unavailable");
      }
    } catch (err) {
      // Only log in development
      if (process.env.NODE_ENV === "development") {
        console.error("Error fetching description:", err);
      }

      // Fall back to cache
      const cachedDesc = getCachedDescription();
      if (cachedDesc) {
        setDescription(cachedDesc);
        setUsingCache(true);
      } else {
        // Use default description if no cache and API unavailable (first run scenario)
        setDescription(DEFAULT_DESCRIPTION);
        // Save default to cache so it's available next time
        saveDescriptionToCache(DEFAULT_DESCRIPTION);
      }
    } finally {
      setLoadingDescription(false);
    }
  };

  useEffect(() => {
    fetchScans();
    fetchDescription();
  }, []);

  // Auto-select most recent completed scan when scans are loaded
  useEffect(() => {
    // Skip if we just completed a scan via polling (to avoid race condition)
    if (recentlyCompletedScanId.current !== null) {
      return;
    }

    if (scans.length > 0) {
      // Find the most recent completed scan
      const completedScans = scans.filter(s => s.status === "completed");
      if (completedScans.length > 0) {
        // Sort by completed_at or requested_at (most recent first)
        const sorted = completedScans.sort((a, b) => {
          const aTime = a.completed_at ? new Date(a.completed_at).getTime() : new Date(a.requested_at).getTime();
          const bTime = b.completed_at ? new Date(b.completed_at).getTime() : new Date(b.requested_at).getTime();
          return bTime - aTime;
        });
        const mostRecent = sorted[0];

        // Only update if we don't have a selected scan, or if the most recent is newer
        if (!selectedScan) {
          loadScanDetails(mostRecent.id);
        } else {
          // Check if the most recent scan is newer than the currently selected one
          const selectedTime = selectedScan.completed_at
            ? new Date(selectedScan.completed_at).getTime()
            : new Date(selectedScan.requested_at).getTime();
          const mostRecentTime = mostRecent.completed_at
            ? new Date(mostRecent.completed_at).getTime()
            : new Date(mostRecent.requested_at).getTime();

          // Update if the most recent scan is newer
          if (mostRecentTime > selectedTime && mostRecent.id !== selectedScan.id) {
            loadScanDetails(mostRecent.id);
          }
        }
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scans]);

  const loadScanDetails = async (scanId: number) => {
    try {
      const response = await fetch(`/api/dns-scanner/scans/${scanId}`);
      if (response.ok) {
        const data = await response.json();
        // Ensure results is always an array (empty if no results)
        setSelectedScan({
          ...data,
          results: data.results || [],
        });
        // Cache results if they exist
        if (data.results && data.results.length > 0) {
          saveResultsToCache(scanId, data.results);
        }
      } else {
        // API failed, try cache
        const cachedResults = getCachedResults(scanId);
        const scan = scans.find(s => s.id === scanId);
        if (scan) {
          setSelectedScan({
            ...scan,
            results: cachedResults.length > 0 ? cachedResults : [],
          });
          if (cachedResults.length > 0) {
            setUsingCache(true);
          }
        }
      }
    } catch (err) {
      // Fall back to cache
      const cachedResults = getCachedResults(scanId);
      const scan = scans.find(s => s.id === scanId);
      if (scan) {
        setSelectedScan({
          ...scan,
          results: cachedResults.length > 0 ? cachedResults : [],
        });
        if (cachedResults.length > 0) {
          setUsingCache(true);
        }
      }
    }
  };

  return (
    <div className="flex flex-col h-full w-full gap-4 overflow-x-hidden max-w-full">
      <h1 className="text-xl font-bold">DNS Vulnerability Scanner</h1>

      {/* Description Banner */}
      {!loadingDescription && description && (
        <Alert
          severity={usingCache ? (cacheStale ? "warning" : "info") : "info"}
          sx={{ mb: 2 }}
          action={
            usingCache && (
              <Chip
                label={cacheStale ? "Stale Cache" : "Cached"}
                size="small"
                color={cacheStale ? "warning" : "default"}
              />
            )
          }
        >
          {description}
          {usingCache && (
            <span className="ml-2 text-xs">
              (HP App Store unavailable - showing cached data)
            </span>
          )}
        </Alert>
      )}

      <Box className="flex gap-2 items-end">
        <TextField
          label="Domain"
          value={domain}
          onChange={(e) => {
            setDomain(e.target.value);
            if (error) setError(null);
          }}
          placeholder="example.edu"
          disabled={loading}
          fullWidth
          helperText={error || "Enter a .edu domain (e.g., example.edu)"}
          error={!!error}
          inputProps={{
            "aria-invalid": !!error,
            "aria-describedby": "domain-helper",
          }}
          FormHelperTextProps={{
            id: "domain-helper",
            role: error ? ("alert" as const) : undefined,
          }}
          onKeyPress={(e) => {
            if (e.key === "Enter" && !loading) {
              handleScan();
            }
          }}
        />
        <Button
          variant="contained"
          onClick={handleScan}
          disabled={loading || !domain.trim()}
        >
          {loading ? <CircularProgress size={20} /> : "Scan"}
        </Button>
      </Box>

      {selectedScan && selectedScan.status === "completed" && (
        <DNSScannerResultsTable
          key={selectedScan.id}
          scanId={selectedScan.id}
          results={selectedScan.results || []}
          domain={selectedScan.domain}
        />
      )}
    </div>
  );
}

