"use client";

import { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@mui/material";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { getUpdateJobStatus, UpdateJobStatus } from "@/lib/update-actions";
import { Loader2, CheckCircle2, XCircle, AlertCircle, RefreshCw } from "lucide-react";
import { toast } from "sonner";

interface UpdateProgressModalProps {
  jobId: string;
  open: boolean;
  onClose: () => void;
}

export function UpdateProgressModal({ jobId, open, onClose }: UpdateProgressModalProps) {
  const [jobStatus, setJobStatus] = useState<UpdateJobStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [polling, setPolling] = useState(true);

  useEffect(() => {
    if (open && jobId) {
      startPolling();
    } else {
      setPolling(false);
    }

    return () => {
      setPolling(false);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, jobId]);

  const startPolling = async () => {
    setPolling(true);
    const pollInterval = setInterval(async () => {
      if (!polling) {
        clearInterval(pollInterval);
        return;
      }

      try {
        const status = await getUpdateJobStatus(jobId);
        setJobStatus(status);
        setLoading(false);

        // Stop polling if job is completed or failed
        if (status.status === 'completed' || status.status === 'failed') {
          clearInterval(pollInterval);
          setPolling(false);

          if (status.status === 'completed') {
            toast.success("Update completed successfully!");
          } else {
            toast.error(`Update failed: ${status.error || 'Unknown error'}`);
          }
        }
      } catch (error: any) {
        console.error("Error polling job status:", error);
        // Continue polling on error
      }
    }, 2000); // Poll every 2 seconds

    // Cleanup on unmount
    return () => clearInterval(pollInterval);
  };

  const getStatusIcon = () => {
    if (!jobStatus) return <Loader2 className="h-5 w-5 animate-spin" />;

    switch (jobStatus.status) {
      case 'completed':
        return <CheckCircle2 className="h-5 w-5 text-green-500" />;
      case 'failed':
        return <XCircle className="h-5 w-5 text-red-500" />;
      case 'in-progress':
        return <Loader2 className="h-5 w-5 animate-spin text-blue-500" />;
      default:
        return <Loader2 className="h-5 w-5 animate-spin" />;
    }
  };

  const getStatusColor = () => {
    if (!jobStatus) return 'text-muted-foreground';

    switch (jobStatus.status) {
      case 'completed':
        return 'text-green-600 dark:text-green-400';
      case 'failed':
        return 'text-red-600 dark:text-red-400';
      case 'in-progress':
        return 'text-blue-600 dark:text-blue-400';
      default:
        return 'text-muted-foreground';
    }
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="sm:max-w-[600px] max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            {getStatusIcon()}
            Update Progress
          </DialogTitle>
          <DialogDescription>
            {jobStatus?.current_version} → {jobStatus?.target_version}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {loading && !jobStatus && (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-8 w-8 animate-spin" />
              <span className="ml-2">Loading update status...</span>
            </div>
          )}

          {jobStatus && (
            <>
              <div className="p-4 bg-muted rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-semibold">Status:</span>
                  <span className={`font-semibold capitalize ${getStatusColor()}`}>
                    {jobStatus.status.replace('-', ' ')}
                  </span>
                </div>
                {jobStatus.error && (
                  <Alert className="mt-2 border-red-200 bg-red-50 dark:bg-red-950">
                    <AlertCircle className="h-4 w-4 text-red-600" />
                    <AlertDescription className="text-red-800 dark:text-red-200">
                      {jobStatus.error}
                    </AlertDescription>
                  </Alert>
                )}
                {jobStatus.rolled_back && (
                  <Alert className="mt-2 border-yellow-200 bg-yellow-50 dark:bg-yellow-950">
                    <AlertCircle className="h-4 w-4 text-yellow-600" />
                    <AlertDescription className="text-yellow-800 dark:text-yellow-200">
                      Update was rolled back due to failure
                    </AlertDescription>
                  </Alert>
                )}
              </div>

              {jobStatus.steps && jobStatus.steps.length > 0 && (
                <div className="space-y-2">
                  <h4 className="font-semibold">Workflow Steps:</h4>
                  <div className="space-y-2">
                    {jobStatus.steps.map((step, index) => (
                      <div
                        key={index}
                        className={`p-3 rounded-lg border ${
                          step.error
                            ? 'border-red-200 bg-red-50 dark:bg-red-950'
                            : step.step === 'completed'
                            ? 'border-green-200 bg-green-50 dark:bg-green-950'
                            : 'border-muted bg-muted'
                        }`}
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <p className="font-medium capitalize">{step.step.replace(/_/g, ' ')}</p>
                            <p className="text-sm text-muted-foreground mt-1">{step.message}</p>
                            {step.error && (
                              <p className="text-sm text-red-600 dark:text-red-400 mt-1">
                                Error: {step.error}
                              </p>
                            )}
                          </div>
                          <span className="text-xs text-muted-foreground">
                            {new Date(step.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {jobStatus.status === 'in-progress' && (
                <div className="flex items-center justify-center py-4">
                  <Loader2 className="h-6 w-6 animate-spin mr-2" />
                  <span>Update in progress...</span>
                </div>
              )}
            </>
          )}
        </div>

        <div className="flex justify-end gap-2 pt-4 border-t">
          {jobStatus?.status === 'completed' || jobStatus?.status === 'failed' ? (
            <Button variant="contained" onClick={onClose}>
              Close
            </Button>
          ) : (
            <Button variant="outlined" onClick={onClose}>
              Close (Update will continue in background)
            </Button>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

