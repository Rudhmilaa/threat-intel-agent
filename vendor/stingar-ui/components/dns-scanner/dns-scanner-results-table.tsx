"use client";

import { useState, useEffect } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Checkbox,
  Chip,
  Button,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from "@mui/material";
import { toast } from "sonner";
import {
  updateResultInCache,
  updateScanInCache,
} from "@/lib/dns-scanner-cache";

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

interface Props {
  scanId: number;
  results: VulnerabilityResult[];
  domain: string;
}

export default function DNSScannerResultsTable({ scanId, results, domain }: Props) {
  const [localResults, setLocalResults] = useState<VulnerabilityResult[]>(results);
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [notesDialog, setNotesDialog] = useState<{ open: boolean; resultId: number | null }>({
    open: false,
    resultId: null,
  });
  const [notes, setNotes] = useState("");
  const [currentScanId, setCurrentScanId] = useState<number>(scanId);

  // Update local results when props change (new scan or updated results)
  useEffect(() => {
    // Ensure results is always an array (defensive coding)
    const safeResults = Array.isArray(results) ? results : [];

    // If scanId changed, it's a completely new scan - reset everything
    if (scanId !== currentScanId) {
      setCurrentScanId(scanId);
      setLocalResults(safeResults);
      setSelectedIds([]);
      setNotesDialog({ open: false, resultId: null });
      setNotes("");
    } else {
      // Same scan, but results may have been updated - update local state
      setLocalResults(safeResults);
    }
  }, [scanId, results, currentScanId]);

  const handleToggleFixed = async (resultId: number, isFixed: boolean) => {
    try {
      const response = await fetch(`/api/dns-scanner/results/${resultId}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          is_fixed: !isFixed,
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to update result");
      }

      const updated = await response.json();
      setLocalResults((prev) =>
        prev.map((r) => (r.id === resultId ? updated : r))
      );

      // Update cache
      updateResultInCache(scanId, updated);

      toast.success(isFixed ? "Marked as not fixed" : "Marked as fixed");
    } catch (err: any) {
      toast.error(err.message);
    }
  };

  const handleBulkUpdate = async (isFixed: boolean) => {
    if (selectedIds.length === 0) return;

    try {
      const response = await fetch(`/api/dns-scanner/results/bulk-update`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          result_ids: selectedIds,
          is_fixed: isFixed,
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to bulk update");
      }

      const updated = await response.json();
      setLocalResults((prev) =>
        prev.map((r) => {
          const found = updated.find((u: VulnerabilityResult) => u.id === r.id);
          return found || r;
        })
      );

      // Update cache for all updated results
      updated.forEach((result: VulnerabilityResult) => {
        updateResultInCache(scanId, result);
      });

      setSelectedIds([]);
      toast.success(`Marked ${selectedIds.length} as ${isFixed ? "fixed" : "not fixed"}`);
    } catch (err: any) {
      toast.error(err.message);
    }
  };

  const handleAddNotes = async () => {
    if (!notesDialog.resultId) return;

    try {
      const response = await fetch(`/api/dns-scanner/results/${notesDialog.resultId}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          notes: notes,
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to update notes");
      }

      const updated = await response.json();
      setLocalResults((prev) =>
        prev.map((r) => (r.id === notesDialog.resultId ? updated : r))
      );

      // Update cache
      if (notesDialog.resultId) {
        updateResultInCache(scanId, updated);
      }

      setNotesDialog({ open: false, resultId: null });
      setNotes("");
      toast.success("Notes updated");
    } catch (err: any) {
      toast.error(err.message);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "error";
      case "high":
        return "warning";
      case "medium":
        return "info";
      case "low":
        return "default";
      default:
        return "default";
    }
  };

  const getResolvedStatus = (result: VulnerabilityResult): boolean => {
    // Check if is_resolved is explicitly set
    if (result.is_resolved !== undefined) {
      return result.is_resolved;
    }
    // Fallback: parse from description if available
    if (result.description) {
      return result.description.includes("Status: Resolved");
    }
    return false;
  };

  // Ensure we have a valid results array
  const displayResults = Array.isArray(localResults) ? localResults : [];

  return (
    <div className="flex flex-col gap-4 overflow-x-hidden max-w-full">
      <div className="flex justify-between items-center flex-wrap gap-2">
        <h3 className="text-lg font-semibold">
          Vulnerability Scans for {domain} ({displayResults.length})
        </h3>
        {selectedIds.length > 0 && (
          <div className="flex gap-2 flex-wrap">
            <Button
              variant="outlined"
              size="small"
              onClick={() => handleBulkUpdate(true)}
            >
              Mark {selectedIds.length} as Fixed
            </Button>
            <Button
              variant="outlined"
              size="small"
              onClick={() => handleBulkUpdate(false)}
            >
              Mark {selectedIds.length} as Not Fixed
            </Button>
          </div>
        )}
      </div>

      <div className="overflow-x-auto max-w-full">
        <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell padding="checkbox">
                <Checkbox
                  indeterminate={
                    selectedIds.length > 0 && selectedIds.length < displayResults.length
                  }
                  checked={
                    displayResults.length > 0 && selectedIds.length === displayResults.length
                  }
                  onChange={(e) => {
                    if (e.target.checked) {
                      setSelectedIds(displayResults.map((r) => r.id));
                    } else {
                      setSelectedIds([]);
                    }
                  }}
                />
              </TableCell>
              <TableCell>URL</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Description</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {displayResults.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} align="center" style={{ padding: '40px' }}>
                  No vulnerabilities found for this domain. The domain appears to be secure.
                </TableCell>
              </TableRow>
            ) : (
              displayResults.map((result) => (
                <TableRow key={result.id}>
                  <TableCell padding="checkbox">
                    <Checkbox
                      checked={selectedIds.includes(result.id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedIds([...selectedIds, result.id]);
                        } else {
                          setSelectedIds(selectedIds.filter((id) => id !== result.id));
                        }
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <span
                      style={{
                        color: getResolvedStatus(result) ? "#28a745" : "#dc3545",
                        fontWeight: "500",
                      }}
                    >
                      {result.url}
                    </span>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={result.severity}
                      color={getSeverityColor(result.severity) as any}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>{result.description}</TableCell>
                  <TableCell>
                    <Checkbox
                      checked={result.is_fixed}
                      onChange={() => handleToggleFixed(result.id, result.is_fixed)}
                    />
                    {result.is_fixed ? "Fixed" : "Open"}
                  </TableCell>
                  <TableCell>
                    <Button
                      size="small"
                      onClick={() => {
                        setNotesDialog({ open: true, resultId: result.id });
                        setNotes(result.notes || "");
                      }}
                    >
                      Notes
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>
      </div>

      <Dialog
        open={notesDialog.open}
        onClose={() => setNotesDialog({ open: false, resultId: null })}
      >
        <DialogTitle>Add Notes</DialogTitle>
        <DialogContent>
          <TextField
            multiline
            rows={4}
            fullWidth
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Add notes about this vulnerability..."
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNotesDialog({ open: false, resultId: null })}>
            Cancel
          </Button>
          <Button onClick={handleAddNotes} variant="contained">
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
}

