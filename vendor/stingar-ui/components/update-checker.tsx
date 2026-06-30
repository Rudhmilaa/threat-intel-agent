"use client";

import { useState, useEffect } from "react";
import { UpdatePopup } from "./update-popup";
import { useRouter } from "next/navigation";

export function UpdateChecker() {
  const [showPopup, setShowPopup] = useState(false);
  const [hasChecked, setHasChecked] = useState(false);
  const router = useRouter();

  useEffect(() => {
    // Check if user dismissed popup
    const dismissed = localStorage.getItem('update_popup_dismissed');
    if (dismissed === 'true') {
      return;
    }

    // Check for updates after a short delay (to allow page to load)
    const timer = setTimeout(async () => {
      try {
        // Use API route instead of server action to avoid hash mismatch issues
        const response = await fetch('/api/system/update-check', {
          cache: 'no-cache',
        });
        
        if (!response.ok) {
          // Silently fail for 401 (auth not configured) or other errors
          if (response.status !== 401) {
            console.error("Error checking for updates:", response.status, response.statusText);
          }
          return;
        }
        
        const updateInfo = await response.json();
        if (updateInfo.update_available) {
          setShowPopup(true);
        }
      } catch (error) {
        // Silently fail - don't show popup if check fails
        // Only log non-network errors (network errors are expected if backend is down)
        if (error instanceof Error && !error.message.includes('fetch')) {
          console.error("Error checking for updates:", error);
        }
      } finally {
        setHasChecked(true);
      }
    }, 2000); // 2 second delay

    return () => clearTimeout(timer);
  }, []);

  const handleInstall = () => {
    setShowPopup(false);
    // Navigate to settings page where user can trigger update
    router.push('/settings?tab=updates');
  };

  const handleLater = () => {
    setShowPopup(false);
  };

  return (
    <UpdatePopup
      open={showPopup}
      onClose={() => setShowPopup(false)}
      onInstall={handleInstall}
      onLater={handleLater}
    />
  );
}

