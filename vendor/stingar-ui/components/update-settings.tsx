"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@mui/material";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch, FormControlLabel, RadioGroup, Radio } from "@mui/material";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  getSystemVersion,
  getUpdateStatus,
  checkForUpdates,
  applyUpdate,
  getUpdateJobStatus,
  getUpdateSettings,
  updateUpdateSettings,
  UpdateSettings,
  UpdateStatusResponse,
} from "@/lib/update-actions";
import { toast } from "sonner";
import { Loader2, RefreshCw, Download, AlertCircle, CheckCircle2, Clock, FileText } from "lucide-react";
import { UpdateProgressModal } from "./update-progress-modal";
import ReactMarkdown from "react-markdown";

export function UpdateSettingsSection() {
  const [version, setVersion] = useState<string | null>(null);
  const [updateStatus, setUpdateStatus] = useState<UpdateStatusResponse | null>(null);
  const [updateCheck, setUpdateCheck] = useState<any>(null);
  const [settings, setSettings] = useState<UpdateSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [checking, setChecking] = useState(false);
  const [applying, setApplying] = useState(false);
  const [showProgressModal, setShowProgressModal] = useState(false);
  const [updateJobId, setUpdateJobId] = useState<string | null>(null);
  const [editedSettings, setEditedSettings] = useState<Partial<UpdateSettings>>({});
  const installSectionRef = useRef<HTMLDivElement>(null);
  const hasScrolledToUpdateRef = useRef(false);
  const [releaseNotesContent, setReleaseNotesContent] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  // Resolve release notes from updateStatus or updateCheck
  const versionInfo =
    updateCheck?.latest_version_info ?? updateStatus?.latest_version_info ?? null;
  const hasUpdate = updateStatus?.update_available || updateCheck?.update_available;

  useEffect(() => {
    if (!hasUpdate || !versionInfo) {
      setReleaseNotesContent(null);
      return;
    }
    if (versionInfo.release_notes) {
      setReleaseNotesContent(versionInfo.release_notes);
      return;
    }
    if (versionInfo.release_notes_url) {
      fetch(versionInfo.release_notes_url)
        .then((r) => (r.ok ? r.text() : null))
        .then(setReleaseNotesContent)
        .catch(() => setReleaseNotesContent(null));
      return;
    }
    setReleaseNotesContent(null);
  }, [hasUpdate, versionInfo?.release_notes, versionInfo?.release_notes_url]);

  // When update is available, scroll Install section into view once (WCAG: aid navigation from badge)
  useEffect(() => {
    const hasUpdate = updateStatus?.update_available || updateCheck?.update_available;
    if (hasUpdate && installSectionRef.current && !hasScrolledToUpdateRef.current) {
      hasScrolledToUpdateRef.current = true;
      installSectionRef.current.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [updateStatus?.update_available, updateCheck?.update_available]);

  const loadData = async () => {
    try {
      setLoading(true);
      const [versionData, statusData, settingsData] = await Promise.all([
        getSystemVersion(),
        getUpdateStatus(),
        getUpdateSettings(),
      ]);
      setVersion(versionData.version);
      setUpdateStatus(statusData);
      setSettings(settingsData);
      setEditedSettings(settingsData);
    } catch (error: any) {
      console.error("Error loading update data:", error);
      toast.error("Failed to load update information");
    } finally {
      setLoading(false);
    }
  };

  const handleCheckForUpdates = async () => {
    try {
      setChecking(true);
      const checkResult = await checkForUpdates();
      setUpdateCheck(checkResult);
      if (checkResult.update_available) {
        toast.success(`Update available: ${checkResult.latest_version}`);
      } else {
        toast.info("You are on the latest version");
      }
    } catch (error: any) {
      console.error("Error checking for updates:", error);
      toast.error("Failed to check for updates");
    } finally {
      setChecking(false);
    }
  };

  const handleApplyUpdate = async () => {
    try {
      setApplying(true);
      const result = await applyUpdate();
      setUpdateJobId(result.job_id);
      setShowProgressModal(true);
      toast.success("Update job started");
    } catch (error: any) {
      console.error("Error applying update:", error);
      toast.error(error.message || "Failed to start update");
    } finally {
      setApplying(false);
    }
  };

  const handleSaveSettings = async () => {
    try {
      setSaving(true);
      await updateUpdateSettings(editedSettings);
      toast.success("Update settings saved");
      await loadData();
    } catch (error: any) {
      console.error("Error saving settings:", error);
      toast.error("Failed to save settings");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <Card>
        <CardContent className="py-8">
          <div className="flex items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin" />
            <span className="ml-2">Loading update information...</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>System Updates</CardTitle>
          <CardDescription>
            Manage automatic updates and version information
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Current Version Info */}
          <div className="grid grid-cols-2 gap-4">
            <div className="p-4 bg-muted rounded-lg">
              <p className="text-sm text-muted-foreground">Current Version</p>
              <p className="text-2xl font-bold">{version || 'Unknown'}</p>
            </div>
            <div className="p-4 bg-blue-50 dark:bg-blue-950 rounded-lg border border-blue-200 dark:border-blue-800">
              <p className="text-sm text-blue-600 dark:text-blue-400">Latest Version</p>
              <p className="text-2xl font-bold text-blue-700 dark:text-blue-300">
                {updateStatus?.latest_version || 'Checking...'}
              </p>
            </div>
          </div>

          {/* Update Check */}
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-semibold">Update Check</h3>
              <p className="text-sm text-muted-foreground">
                Check if a new version is available
              </p>
            </div>
            <Button
              variant="outlined"
              onClick={handleCheckForUpdates}
              disabled={checking}
              startIcon={checking ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
            >
              {checking ? 'Checking...' : 'Check for Updates'}
            </Button>
          </div>

          {((updateStatus?.update_available) || (updateCheck?.update_available)) && (
            <Alert
              ref={installSectionRef}
              role="status"
              aria-live="polite"
              aria-label="Update available"
              className="border-2 border-blue-500 bg-blue-50 dark:bg-blue-950 shadow-md ring-2 ring-blue-200 dark:ring-blue-800"
            >
              <AlertCircle className="h-4 w-4 text-blue-600 dark:text-blue-400" aria-hidden="true" />
              <AlertDescription className="text-blue-800 dark:text-blue-200">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                  <div>
                    <p className="font-semibold text-base">
                      Update Available: {updateCheck?.latest_version || updateStatus?.latest_version || "New version"}
                    </p>
                    {!(updateCheck?.within_update_window ?? updateStatus?.update_window?.within_window) && (
                      <p className="text-sm mt-1">
                        Outside update window (
                        {(updateCheck?.update_window || updateStatus?.update_window)?.start} -{" "}
                        {(updateCheck?.update_window || updateStatus?.update_window)?.end})
                      </p>
                    )}
                  </div>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={handleApplyUpdate}
                    disabled={
                      applying ||
                      !(updateCheck?.within_update_window ?? updateStatus?.update_window?.within_window)
                    }
                    startIcon={
                      applying ? (
                        <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                      ) : (
                        <Download className="h-4 w-4" aria-hidden="true" />
                      )
                    }
                    className="min-w-[140px] focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                    aria-label="Install update to latest version"
                  >
                    {applying ? "Starting..." : "Install Update"}
                  </Button>
                </div>
              </AlertDescription>
            </Alert>
          )}

          {hasUpdate && releaseNotesContent && (
            <div
              className="border rounded-lg p-4 bg-muted/50 dark:bg-muted/20 max-h-[400px] overflow-y-auto"
              role="region"
              aria-label="Release notes for available update"
            >
              <h3 className="font-semibold flex items-center gap-2 mb-3">
                <FileText className="h-4 w-4" aria-hidden="true" />
                Release Notes
              </h3>
              <div className="text-sm [&_h1]:text-lg [&_h1]:font-bold [&_h2]:text-base [&_h2]:font-semibold [&_h3]:text-sm [&_h3]:font-semibold [&_ul]:list-disc [&_ul]:pl-5 [&_ol]:list-decimal [&_ol]:pl-5 [&_p]:mb-2 [&_hr]:my-3 [&_a]:text-blue-600 [&_a]:underline">
                <ReactMarkdown
                  components={{
                    a: ({ href, children }) => (
                      <a
                        href={href}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-blue-600 dark:text-blue-400 underline focus-visible:ring-2 focus-visible:ring-blue-500 rounded"
                      >
                        {children}
                      </a>
                    ),
                  }}
                >
                  {releaseNotesContent}
                </ReactMarkdown>
              </div>
            </div>
          )}

          {/* Update Settings */}
          {settings && (
            <div className="space-y-4 border-t pt-4">
              <h3 className="font-semibold">Update Settings</h3>

              <div className="space-y-4">
                <div>
                  <Label className="mb-2 block">Update Mode</Label>
                  <RadioGroup
                    value={editedSettings.update_mode || settings.update_mode}
                    onChange={(e) => setEditedSettings({ ...editedSettings, update_mode: e.target.value as 'manual' | 'auto' })}
                  >
                    <FormControlLabel value="manual" control={<Radio />} label="Manual (Requires user approval)" />
                    <FormControlLabel value="auto" control={<Radio />} label="Automatic (Apply updates automatically)" />
                  </RadioGroup>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="window-start">Update Window Start</Label>
                    <Input
                      id="window-start"
                      type="time"
                      value={editedSettings.update_window_start || settings.update_window_start}
                      onChange={(e) => setEditedSettings({ ...editedSettings, update_window_start: e.target.value })}
                    />
                  </div>
                  <div>
                    <Label htmlFor="window-end">Update Window End</Label>
                    <Input
                      id="window-end"
                      type="time"
                      value={editedSettings.update_window_end || settings.update_window_end}
                      onChange={(e) => setEditedSettings({ ...editedSettings, update_window_end: e.target.value })}
                    />
                  </div>
                </div>

                <div>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={editedSettings.service_enabled ?? settings.service_enabled}
                        onChange={(e) => setEditedSettings({ ...editedSettings, service_enabled: e.target.checked })}
                      />
                    }
                    label="Enable Update Service"
                  />
                  <p className="text-sm text-muted-foreground ml-10">
                    When enabled, the system will automatically check for updates
                  </p>
                </div>

                <div>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={editedSettings.cleanup_old_images ?? settings.cleanup_old_images}
                        onChange={(e) => setEditedSettings({ ...editedSettings, cleanup_old_images: e.target.checked })}
                      />
                    }
                    label="Cleanup Old Images"
                  />
                  <p className="text-sm text-muted-foreground ml-10">
                    Automatically remove old Docker images after updates
                  </p>
                </div>

                <Button
                  variant="contained"
                  onClick={handleSaveSettings}
                  disabled={saving}
                  startIcon={saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <CheckCircle2 className="h-4 w-4" />}
                >
                  {saving ? 'Saving...' : 'Save Settings'}
                </Button>
              </div>
            </div>
          )}

          {/* Update Status */}
          {updateStatus && (
            <div className="border-t pt-4">
              <h3 className="font-semibold mb-2">Update Service Status</h3>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Service Enabled:</span>
                  <span>{updateStatus.service_enabled ? 'Yes' : 'No'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Remote Store:</span>
                  <span>{updateStatus.remote_store_enabled ? 'Connected' : 'Disconnected'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Check Interval:</span>
                  <span>{Math.floor(updateStatus.check_interval / 3600)} hours</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Update Window:</span>
                  <span>
                    {updateStatus.update_window.start} - {updateStatus.update_window.end}
                    {updateStatus.update_window.within_window && (
                      <Clock className="h-3 w-3 inline ml-1 text-green-500" />
                    )}
                  </span>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {showProgressModal && updateJobId && (
        <UpdateProgressModal
          jobId={updateJobId}
          open={showProgressModal}
          onClose={() => {
            setShowProgressModal(false);
            setUpdateJobId(null);
            loadData(); // Refresh data after update
          }}
        />
      )}
    </>
  );
}

