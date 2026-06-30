'use client';

import { useState, useEffect } from 'react';

interface SystemVersion {
    version: string;
    version_state_file?: string;
    compose_file?: string;
    installed_date?: string;
    last_check?: string;
    images_pulled?: boolean;
    images_pulled_date?: string;
}

interface SelfVersion {
    service: string;
    version: string;
    source: string;
}

// Normalize "v2.3" / "2.3" / "  v2.3  " -> "v2.3" for skew comparison.
// Returns null for unusable values ("", "unknown", null).
function normalizeVersion(raw: string | null | undefined): string | null {
    if (!raw) return null;
    const trimmed = raw.trim();
    if (!trimmed || trimmed === 'unknown' || trimmed === 'Unknown') return null;
    return trimmed.startsWith('v') ? trimmed : 'v' + trimmed;
}

export function useSystemVersion() {
    // version = the version the dashboard should display ("current installed")
    // - reported by apiarist via /api/system/version (preferred)
    // - falls back to UI self-version if apiarist is unreachable
    const [version, setVersion] = useState<string | null>(null);
    // selfVersion = the UI container's own STINGAR_VERSION
    const [selfVersion, setSelfVersion] = useState<string | null>(null);
    // versionSkew = true iff apiarist version != UI self version
    //               (both must be known/normalized for skew to be flagged)
    const [versionSkew, setVersionSkew] = useState<boolean>(false);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let cancelled = false;

        async function fetchApiaristVersion(): Promise<string | null> {
            try {
                const response = await fetch('/api/system/version', { cache: 'no-cache' });
                if (response.status === 401) {
                    // Backend not configured (common in dev) - not an error.
                    return null;
                }
                if (!response.ok) {
                    throw new Error(`Failed to fetch version: ${response.statusText}`);
                }
                const info: SystemVersion = await response.json();
                return info.version || null;
            } catch (err) {
                if (!(err instanceof Error && err.message.includes('401'))) {
                    console.error('Failed to fetch apiarist-reported version:', err);
                }
                throw err;
            }
        }

        async function fetchSelfVersion(): Promise<string | null> {
            try {
                const response = await fetch('/api/system/self-version', { cache: 'no-cache' });
                if (!response.ok) return null;
                const info: SelfVersion = await response.json();
                return info.version || null;
            } catch (err) {
                // Self-version is best-effort; do not surface to the user.
                console.debug('Failed to fetch UI self-version:', err);
                return null;
            }
        }

        async function load() {
            setLoading(true);
            // Fetch in parallel - UI self-version never depends on apiarist.
            const [apiaristResult, selfResult] = await Promise.allSettled([
                fetchApiaristVersion(),
                fetchSelfVersion(),
            ]);

            if (cancelled) return;

            const apiaristVersion =
                apiaristResult.status === 'fulfilled' ? apiaristResult.value : null;
            const self = selfResult.status === 'fulfilled' ? selfResult.value : null;

            // Display priority: apiarist > UI self > NEXT_PUBLIC_VERSION env (dev).
            const displayed =
                apiaristVersion || self || process.env.NEXT_PUBLIC_VERSION || null;
            setVersion(displayed);
            setSelfVersion(self);

            // Skew is only meaningful if both versions are known.
            const a = normalizeVersion(apiaristVersion);
            const s = normalizeVersion(self);
            setVersionSkew(Boolean(a && s && a !== s));

            if (apiaristResult.status === 'rejected') {
                const err = apiaristResult.reason;
                setError(err instanceof Error ? err.message : 'Unknown error');
            } else {
                setError(null);
            }

            setLoading(false);
        }

        load();
        return () => {
            cancelled = true;
        };
    }, []);

    return { version, selfVersion, versionSkew, loading, error };
}
