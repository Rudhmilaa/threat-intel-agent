import { useState, useEffect } from 'react';
import { getStoreCount } from '@/lib/actions';
import { debugLog } from '@/lib/debug';

// Note: This hook is deprecated. Use useStoreCountContext instead for better state management.

export function useStoreCount() {
    const [count, setCount] = useState<number | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const fetchCount = async () => {
        try {
            setLoading(true);
            setError(null);
            debugLog('Fetching store count...');

            // Use server action to get store count
            const data = await getStoreCount();
            debugLog('Store count response:', data);
            setCount(data.data.count);
            debugLog('Set count to:', data.data.count);
        } catch (err) {
            console.error('Failed to fetch store count:', err);
            setError(err instanceof Error ? err.message : 'Failed to fetch count');
            setCount(null);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchCount();
    }, []);

    debugLog('useStoreCount hook - count:', count, 'loading:', loading, 'error:', error);
    return { count, loading, error, refetch: fetchCount };
}
