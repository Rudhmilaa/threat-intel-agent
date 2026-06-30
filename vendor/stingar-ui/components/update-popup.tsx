"use client";

import { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@mui/material";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { checkForUpdates, UpdateCheckResponse } from "@/lib/update-actions";
import { useSystemVersion } from "@/lib/hooks/use-system-version";
import { ExternalLink, AlertCircle, CheckCircle2, Clock, AlertTriangle } from "lucide-react";
import { toast } from "sonner";

interface UpdatePopupProps {
  open: boolean;
  onClose: () => void;
  onInstall: () => void;
  onLater: () => void;
}

export function UpdatePopup({ open, onClose, onInstall, onLater }: UpdatePopupProps) {
  const [updateInfo, setUpdateInfo] = useState<UpdateCheckResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [dontShowAgain, setDontShowAgain] = useState(false);
  // Pull the UI container's own STINGAR_VERSION so we can warn the
  // operator when apiarist's reported current_version disagrees with
  // what's actually running. See Roadmap/plans/VERSIONING_OVERHAUL_PLAN.md.
  const { selfVersion, versionSkew } = useSystemVersion();

  useEffect(() => {
    if (open) {
      loadUpdateInfo();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const loadUpdateInfo = async () => {
    try {
      setLoading(true);
      const info = await checkForUpdates();
      setUpdateInfo(info);
    } catch (error: any) {
      console.error("Error checking for updates:", error);
      toast.error("Failed to check for updates");
      onClose();
    } finally {
      setLoading(false);
    }
  };

  const handleInstall = () => {
    if (dontShowAgain) {
      localStorage.setItem('update_popup_dismissed', 'true');
    }
    onInstall();
  };

  const handleLater = () => {
    if (dontShowAgain) {
      localStorage.setItem('update_popup_dismissed', 'true');
    }
    onLater();
  };

  if (!open || !updateInfo) {
    return null;
  }

  if (!updateInfo.update_available) {
    return null;
  }

  const latestVersion = updateInfo.latest_version_info;

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[500px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <AlertCircle className="h-5 w-5 text-blue-500" />
            New Version Available
          </DialogTitle>
          <DialogDescription>
            A new version of STINGAR is available for installation.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div className="p-3 bg-muted rounded-lg">
              <p className="text-sm text-muted-foreground">Current Version</p>
              <p className="text-lg font-semibold">{updateInfo.current_version || 'Unknown'}</p>
            </div>
            <div className="p-3 bg-blue-50 dark:bg-blue-950 rounded-lg border border-blue-200 dark:border-blue-800">
              <p className="text-sm text-blue-600 dark:text-blue-400">Latest Version</p>
              <p className="text-lg font-semibold text-blue-700 dark:text-blue-300">
                {updateInfo.latest_version}
              </p>
            </div>
          </div>

          {latestVersion && (
            <div className="space-y-2">
              {latestVersion.mandatory && (
                <Alert className="border-red-200 bg-red-50 dark:bg-red-950">
                  <AlertCircle className="h-4 w-4 text-red-600" />
                  <AlertDescription className="text-red-800 dark:text-red-200">
                    This is a mandatory update. Please install it as soon as possible.
                  </AlertDescription>
                </Alert>
              )}

              {latestVersion.breaking_changes && (
                <Alert className="border-orange-200 bg-orange-50 dark:bg-orange-950">
                  <AlertCircle className="h-4 w-4 text-orange-600" />
                  <AlertDescription className="text-orange-800 dark:text-orange-200">
                    This update contains breaking changes. Review the changelog before installing.
                  </AlertDescription>
                </Alert>
              )}

              {latestVersion.update_instructions && (
                <div className="p-3 bg-muted rounded-lg">
                  <p className="text-sm font-semibold mb-1">Update Instructions:</p>
                  <p className="text-sm text-muted-foreground">{latestVersion.update_instructions}</p>
                </div>
              )}

              {latestVersion.changelog && (
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={<ExternalLink className="h-4 w-4" aria-hidden />}
                  href={latestVersion.changelog}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-full"
                  aria-label="View Changelog (opens in new tab)"
                >
                  View Changelog
                </Button>
              )}
            </div>
          )}

          {!updateInfo.within_update_window && (
            <Alert className="border-yellow-200 bg-yellow-50 dark:bg-yellow-950">
              <Clock className="h-4 w-4 text-yellow-600" />
              <AlertDescription className="text-yellow-800 dark:text-yellow-200">
                Outside update window ({updateInfo.update_window.start} - {updateInfo.update_window.end}).
                Update will be scheduled for the next window.
              </AlertDescription>
            </Alert>
          )}

          {versionSkew && selfVersion && (
            <Alert className="border-amber-200 bg-amber-50 dark:bg-amber-950">
              <AlertTriangle className="h-4 w-4 text-amber-600" />
              <AlertDescription className="text-amber-800 dark:text-amber-200">
                <span className="font-semibold">Version mismatch detected.</span>{" "}
                Apiarist reports the installed version as{" "}
                <span className="font-mono">{updateInfo.current_version || "Unknown"}</span>,
                but the UI container is running{" "}
                <span className="font-mono">{selfVersion}</span>. This usually
                resolves itself the next time apiarist restarts. If the
                mismatch persists, restart the apiarist container so it can
                re-detect the current image versions.
              </AlertDescription>
            </Alert>
          )}

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="dont-show-again"
              checked={dontShowAgain}
              onChange={(e) => setDontShowAgain(e.target.checked)}
              className="h-4 w-4"
            />
            <label htmlFor="dont-show-again" className="text-sm text-muted-foreground cursor-pointer">
              Don&apos;t show this again
            </label>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outlined" onClick={handleLater}>
            Later
          </Button>
          <Button
            variant="contained"
            onClick={handleInstall}
            disabled={loading}
            startIcon={<CheckCircle2 className="h-4 w-4" />}
          >
            Install Now
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

