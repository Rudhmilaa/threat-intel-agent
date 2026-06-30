"use client";

import { useState, useEffect } from "react";

export function useUpdateCheck() {
  const [updateAvailable, setUpdateAvailable] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    async function checkForUpdates() {
      try {
        const response = await fetch("/api/system/update-check", {
          cache: "no-cache",
        });

        if (!response.ok) {
          if (response.status !== 401) {
            console.error("Error checking for updates:", response.status);
          }
          return;
        }

        const data = await response.json();
        setUpdateAvailable(data.update_available === true);
      } catch (error) {
        if (error instanceof Error && !error.message.includes("fetch")) {
          console.error("Error checking for updates:", error);
        }
      } finally {
        setIsLoading(false);
      }
    }

    checkForUpdates();
  }, []);

  return { updateAvailable, isLoading };
}
