"use client";

import { useState } from "react";
import useSWR from "swr";
import {
  Box,
  Button,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  TextField,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  CircularProgress,
  Alert,
  Collapse,
  IconButton,
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import RefreshIcon from "@mui/icons-material/Refresh";
import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import { toast } from "sonner";
import {
  getIdsRulesSignatures,
  getIdsRulesExportBlob,
  getIdsRulesPreviewText,
  getIdsRulesStatus,
  type IdsRulesParams,
  type IdsSignature,
  type IdsRulesFormat,
} from "@/lib/actions";
import { useStingarEnv } from "@/lib/hooks/use-stingar-env";
import { format } from "date-fns";

const FEED_DATE_OPTIONS = [
  { value: "30d", label: "Last 30 days" },
  { value: "7d", label: "Last 7 days" },
  { value: "24h", label: "Last 24 hours" },
  { value: "12h", label: "Last 12 hours" },
  { value: "3h", label: "Last 3 hours" },
  { value: "1h", label: "Last 1 hour" },
];

export default function IDSRulesPage() {
  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

  const [fromDate, setFromDate] = useState(format(weekAgo, "yyyy-MM-dd"));
  const [toDate, setToDate] = useState(format(now, "yyyy-MM-dd"));
  const [app, setApp] = useState<"all" | "cowrie" | "dionaea">("all");
  const [ruleTypes, setRuleTypes] = useState("hassh,ja3");
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [previewExpanded, setPreviewExpanded] = useState(false);
  const [previewFormat, setPreviewFormat] = useState<IdsRulesFormat>("suricata");
  const [previewText, setPreviewText] = useState("");
  const [previewEdited, setPreviewEdited] = useState(false);
  const [signatures, setSignatures] = useState<IdsSignature[]>([]);
  const [summary, setSummary] = useState<{
    totalHassh: number;
    totalJa3: number;
    totalJa3s: number;
    totalSshSoftware?: number;
    dateRange: { from: string; to: string };
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const { variables, updateVariables } = useStingarEnv();
  const feedDateRangeVar = variables.find((v) => v.name === "IDS_RULES_FEED_DATE_RANGE");
  const feedDateRangeRaw = feedDateRangeVar?.raw_value ?? feedDateRangeVar?.value ?? "30d";
  const feedDateRange = FEED_DATE_OPTIONS.some((o) => o.value === feedDateRangeRaw)
    ? feedDateRangeRaw
    : "30d";

  const { data: statusData, mutate: mutateStatus } = useSWR(
    "ids-rules-status",
    () => getIdsRulesStatus(),
    { refreshInterval: 60000, revalidateOnFocus: false }
  );
  const feedStatus = statusData?.data;

  const handleFeedDateRangeChange = async (value: string) => {
    try {
      await updateVariables({ IDS_RULES_FEED_DATE_RANGE: value });
      toast.success("Feed date range updated. Takes effect on next background job run.");
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Failed to update feed settings");
    }
  };

  const params: IdsRulesParams = {
    fromDate: `${fromDate}T00:00:00`,
    toDate: `${toDate}T23:59:59`,
    app,
    ruleTypes,
    limit: 500,
  };

  const paramsWithFormat = (format: IdsRulesFormat): IdsRulesParams => ({
    ...params,
    format,
  });

  const handleExtract = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await getIdsRulesSignatures(params);
      setSignatures(result.data.signatures || []);
      setSummary(result.data.summary || null);
      const rulesText = await getIdsRulesPreviewText(paramsWithFormat(previewFormat));
      setPreviewText(rulesText);
      setPreviewEdited(false);
      setPreviewExpanded(true);
      toast.success(
        `Extracted ${result.data.signatures?.length || 0} signatures`
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to extract signatures";
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleRefreshPreview = async () => {
    setLoading(true);
    setError(null);
    try {
      const rulesText = await getIdsRulesPreviewText(paramsWithFormat(previewFormat));
      setPreviewText(rulesText);
      setPreviewEdited(false);
      toast.success("Preview refreshed from API");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to refresh preview";
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const handlePreviewFormatChange = async (_: React.SyntheticEvent, newFormat: string) => {
    const fmt = newFormat as IdsRulesFormat;
    if (fmt !== "suricata" && fmt !== "snort") return;
    setPreviewFormat(fmt);
    if (signatures.length > 0) {
      setLoading(true);
      try {
        const rulesText = await getIdsRulesPreviewText(paramsWithFormat(fmt));
        setPreviewText(rulesText);
        setPreviewEdited(false);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Failed to load preview";
        toast.error(msg);
      } finally {
        setLoading(false);
      }
    }
  };

  const handleExport = async () => {
    setExporting(true);
    setError(null);
    try {
      let content: string;
      if (previewEdited && previewText) {
        content = previewText;
      } else {
        content = await getIdsRulesPreviewText(paramsWithFormat(previewFormat));
      }
      const filename = previewFormat === "snort" ? "stingar-honeypot-snort.rules" : "stingar-honeypot.rules";
      const blob = new Blob([content], { type: "text/plain; charset=utf-8" });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      toast.success("Rules file downloaded");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to export rules";
      setError(msg);
      toast.error(msg);
    } finally {
      setExporting(false);
    }
  };

  const handleCopyToClipboard = async () => {
    const text = previewEdited && previewText ? previewText : await getIdsRulesPreviewText(paramsWithFormat(previewFormat)).catch(() => "");
    if (!text) {
      toast.error("No rules to copy. Extract signatures first.");
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      toast.success("Rules copied to clipboard");
    } catch (err: unknown) {
      toast.error("Failed to copy to clipboard");
    }
  };

  return (
    <div className="flex flex-col h-full w-full overflow-x-hidden max-w-full">
      <h1 className="pb-4 text-xl font-bold">IDS/IPS Rules</h1>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Extract HASSH (SSH) and JA3 (TLS) fingerprints from honeypot sessions
        and export Suricata or Snort rules for deployment to an IDS device.
      </Typography>

      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2, mb: 3 }}>
        <TextField
          label="From Date"
          type="date"
          value={fromDate}
          onChange={(e) => setFromDate(e.target.value)}
          InputLabelProps={{ shrink: true }}
          size="small"
          sx={{ minWidth: 160 }}
        />
        <TextField
          label="To Date"
          type="date"
          value={toDate}
          onChange={(e) => setToDate(e.target.value)}
          InputLabelProps={{ shrink: true }}
          size="small"
          sx={{ minWidth: 160 }}
        />
        <FormControl size="small" sx={{ minWidth: 140 }}>
          <InputLabel>Honeypot</InputLabel>
          <Select
            value={app}
            label="Honeypot"
            onChange={(e) => setApp(e.target.value as "all" | "cowrie" | "dionaea")}
          >
            <MenuItem value="all">All</MenuItem>
            <MenuItem value="cowrie">Cowrie</MenuItem>
            <MenuItem value="dionaea">Dionaea</MenuItem>
          </Select>
        </FormControl>
        <TextField
          label="Rule Types"
          value={ruleTypes}
          onChange={(e) => setRuleTypes(e.target.value)}
          placeholder="hassh,ja3,ja3s,ssh_software"
          size="small"
          sx={{ minWidth: 160 }}
        />
        <Button
          variant="contained"
          onClick={handleExtract}
          disabled={loading}
          startIcon={loading ? <CircularProgress size={16} /> : null}
        >
          {loading ? "Extracting..." : "Extract Signatures"}
        </Button>
        <Button
          variant="outlined"
          onClick={handleExport}
          disabled={exporting}
          startIcon={exporting ? <CircularProgress size={16} /> : null}
        >
          {exporting ? "Exporting..." : "Export Rules"}
        </Button>
        <Button
          variant="outlined"
          onClick={handleCopyToClipboard}
          disabled={!previewText && !signatures.length}
          startIcon={<ContentCopyIcon />}
        >
          Copy to Clipboard
        </Button>
      </Box>

      <Paper sx={{ mb: 2, p: 2 }}>
        <Typography variant="subtitle1" fontWeight="medium" sx={{ mb: 2 }}>
          Auto-generated Feed
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          IDS devices can pull rules from a stable feed URL. A background job regenerates
          rules periodically. Configure the lookback window below.
        </Typography>
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 2, alignItems: "center" }}>
          <FormControl size="small" sx={{ minWidth: 180 }}>
            <InputLabel>Feed date range</InputLabel>
            <Select
              value={feedDateRange}
              label="Feed date range"
              onChange={(e) => handleFeedDateRangeChange(e.target.value)}
            >
              {FEED_DATE_OPTIONS.map((opt) => (
                <MenuItem key={opt.value} value={opt.value}>
                  {opt.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          {feedStatus && (
            <Typography variant="body2" color="text.secondary">
              {feedStatus.lastGenerated
                ? `Last generated: ${format(new Date(feedStatus.lastGenerated), "yyyy-MM-dd HH:mm")} UTC`
                : "Not yet generated"}
              {feedStatus.lastGenerated && (
                <> | HASSH: {feedStatus.totalHassh} | JA3: {feedStatus.totalJa3} | JA3S: {feedStatus.totalJa3s}</>
              )}
            </Typography>
          )}
        </Box>
        <Box sx={{ mt: 1, display: "flex", flexDirection: "column", gap: 0.5 }}>
          <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>
            Suricata: GET /api/v2/ids-rules/feed?format=suricata (requires API-KEY)
          </Typography>
          <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>
            Snort: GET /api/v2/ids-rules/feed?format=snort (requires API-KEY)
          </Typography>
        </Box>
      </Paper>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {summary && (
        <Typography variant="body2" sx={{ mb: 2 }}>
          HASSH: {summary.totalHassh} | JA3: {summary.totalJa3} | JA3S:{" "}
          {summary.totalJa3s}
          {summary.totalSshSoftware !== undefined && summary.totalSshSoftware > 0 && (
            <> | SSH Software: {summary.totalSshSoftware}</>
          )}
        </Typography>
      )}

      {previewText && (
        <Paper sx={{ mb: 2 }}>
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              px: 2,
              py: 1,
              borderBottom: 1,
              borderColor: "divider",
              cursor: "pointer",
            }}
            onClick={() => setPreviewExpanded(!previewExpanded)}
          >
            <Typography variant="subtitle1" fontWeight="medium">
              Preview Rules
              {previewEdited && (
                <Typography component="span" color="text.secondary" sx={{ ml: 1, fontSize: "0.85rem" }}>
                  (edited)
                </Typography>
              )}
            </Typography>
            <IconButton size="small">
              {previewExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
            </IconButton>
          </Box>
          <Collapse in={previewExpanded}>
            <Box sx={{ p: 2, display: "flex", flexDirection: "column", gap: 1 }}>
              <Tabs value={previewFormat} onChange={handlePreviewFormatChange} sx={{ minHeight: 36, mb: 1 }}>
                <Tab label="Suricata" value="suricata" sx={{ minHeight: 36, py: 0 }} />
                <Tab label="Snort" value="snort" sx={{ minHeight: 36, py: 0 }} />
              </Tabs>
              <Box sx={{ display: "flex", gap: 1, justifyContent: "flex-end" }}>
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={<RefreshIcon />}
                  onClick={(e) => {
                    e.stopPropagation();
                    handleRefreshPreview();
                  }}
                  disabled={loading}
                >
                  Refresh from API
                </Button>
              </Box>
              <TextField
                multiline
                minRows={8}
                maxRows={20}
                value={previewText}
                onChange={(e) => {
                  setPreviewText(e.target.value);
                  setPreviewEdited(true);
                }}
                sx={{
                  "& .MuiInputBase-input": {
                    fontFamily: "monospace",
                    fontSize: "0.85rem",
                  },
                }}
                placeholder="Rules will appear here after Extract Signatures..."
              />
            </Box>
          </Collapse>
        </Paper>
      )}

      <TableContainer component={Paper} sx={{ maxHeight: 440 }}>
        <Table stickyHeader size="small">
          <TableHead>
            <TableRow>
              <TableCell>Type</TableCell>
              <TableCell>Hash</TableCell>
              <TableCell>Source</TableCell>
              <TableCell align="right">Count</TableCell>
              <TableCell>First Seen</TableCell>
              <TableCell>Source IPs</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {signatures.length === 0 && !loading && (
              <TableRow>
                <TableCell colSpan={6} align="center" sx={{ py: 4 }}>
                  Click &quot;Extract Signatures&quot; to load data from
                  Elasticsearch
                </TableCell>
              </TableRow>
            )}
            {signatures.map((sig, idx) => (
              <TableRow key={`${sig.type}-${sig.hash}-${idx}`}>
                <TableCell>{sig.type.toUpperCase()}</TableCell>
                <TableCell sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>
                  {sig.hash}
                </TableCell>
                <TableCell>{sig.source}</TableCell>
                <TableCell align="right">{sig.count}</TableCell>
                <TableCell>{sig.firstSeen}</TableCell>
                <TableCell>
                  {sig.srcIps?.slice(0, 3).join(", ") || "-"}
                  {sig.srcIps && sig.srcIps.length > 3
                    ? ` (+${sig.srcIps.length - 3})`
                    : ""}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
    </div>
  );
}
