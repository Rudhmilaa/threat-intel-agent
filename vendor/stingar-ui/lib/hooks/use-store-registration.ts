"use client";

/**
 * Store Registration Hook
 * 
 * NOTE: Registration is now handled automatically by Apiarist on startup.
 * This hook is kept for backward compatibility but only checks store availability.
 * The UI doesn't need to know about API keys or registration - Apiarist handles it all.
 */

import { useState, useEffect, useCallback } from 'react';

interface RegistrationState {
    isRegistered: boolean;  // Actually means "store is available"
    isRegistering: boolean;
    error: string | null;
}

export function useStoreRegistration() {
    const [state, setState] = useState<RegistrationState>({
        isRegistered: false,
        isRegistering: false,
        error: null
    });

    // Check if store is available (registration is handled by Apiarist)
    const checkRegistration = useCallback(async () => {
        try {
            // Just check if store is available - Apiarist handles registration automatically
            const storeResponse = await fetch('/api/store/honeypots?limit=1');

            if (storeResponse.ok || storeResponse.status === 404) {
                // Store is available (404 is OK - just means no honeypots yet)
                setState(prev => ({ ...prev, isRegistered: true }));
                return true;
            } else if (storeResponse.status === 503) {
                // Store unavailable - Apiarist might be registering or there's a config issue
                setState(prev => ({ ...prev, isRegistered: false }));
                return false;
            } else {
                // Other error
                setState(prev => ({ ...prev, isRegistered: false }));
                return false;
            }
        } catch (error) {
            // Assume not available if check fails
            setState(prev => ({ ...prev, isRegistered: false }));
            return false;
        }
    }, []);

    // Check store availability on mount (registration happens automatically in Apiarist)
    useEffect(() => {
        let mounted = true;
        let hasChecked = false;

        const checkAvailability = async () => {
            if (hasChecked || !mounted) {
                return;
            }
            hasChecked = true;

            try {
                // Give Apiarist a moment to complete auto-registration if needed
                await new Promise(resolve => setTimeout(resolve, 2000));

                if (mounted) {
                    await checkRegistration();
                }
            } catch (error) {
                // Silently handle errors - registration is automatic in Apiarist
            }
        };

        checkAvailability();

        return () => {
            mounted = false;
        };
    }, [checkRegistration]);

    // Legacy function - registration is now automatic in Apiarist
    const registerInstance = useCallback(async () => {
        console.warn('[Registration] registerInstance() called but registration is automatic in Apiarist');
        // Just check availability - Apiarist handles registration
        return await checkRegistration();
    }, [checkRegistration]);

    return {
        ...state,
        registerInstance,  // Kept for backward compatibility
        checkRegistration
    };
}
