"use client";

import { useId, useState } from "react";
import { Popover, Typography, Box } from "@mui/material";

const OUTCOME_COLORS: Record<string, string> = {
  benign: "#3d751c",
  malicious: "#bd271e",
  suspicious: "#f5a700",
  unknown: "#646a73",
};

export type OutcomeSummary = {
  scanner_vendor?: string;
  scanner_attribution?: string;
  matched_cidr?: string;
  classification?: string;
  priority?: string;
  frequency_tier?: string;
  events_today?: number;
  behavior_tags?: string[];
  reasons?: string[];
  inventory_version?: number;
};

function enrichmentBlock(row: Record<string, unknown>) {
  const hp = (row.hpData ?? row.hp_data) as Record<string, unknown> | undefined;
  return (hp?.enrichment ?? {}) as Record<string, unknown>;
}

export function resolveCategory(row: Record<string, unknown>): string {
  const direct = row.outcome_category ?? row.outcomeCategory;
  if (typeof direct === "string" && direct) return direct;

  const scannerLite = enrichmentBlock(row).scanner_lite as Record<string, unknown> | undefined;
  const investigation = enrichmentBlock(row).investigation as Record<string, unknown> | undefined;
  return (
    (investigation?.category as string) ||
    (scannerLite?.outcome_category as string) ||
    "unknown"
  );
}

export function resolveSummary(row: Record<string, unknown>): OutcomeSummary {
  const direct = (row.outcome_summary ?? row.outcomeSummary) as OutcomeSummary | undefined;
  if (direct && Object.keys(direct).length > 0) return direct;

  const scannerLite = enrichmentBlock(row).scanner_lite as Record<string, unknown> | undefined;
  if (!scannerLite) return {};
  return {
    scanner_vendor: scannerLite.scanner_vendor as string | undefined,
    scanner_attribution: scannerLite.scanner_attribution as string | undefined,
    matched_cidr: scannerLite.matched_cidr as string | undefined,
    classification: scannerLite.classification as string | undefined,
    priority: scannerLite.priority as string | undefined,
    frequency_tier: scannerLite.frequency_tier as string | undefined,
    events_today: scannerLite.events_today as number | undefined,
    behavior_tags: scannerLite.behavior_tags as string[] | undefined,
    reasons: scannerLite.reasons as string[] | undefined,
    inventory_version: scannerLite.inventory_version as number | undefined,
  };
}

function MetadataRow({ label, value }: { label: string; value?: string | number | null }) {
  if (value == null || value === "") return null;
  return (
    <Box sx={{ display: "flex", gap: 1, py: 0.25 }}>
      <Typography variant="caption" sx={{ fontWeight: 600, minWidth: 110, color: "text.secondary" }}>
        {label}
      </Typography>
      <Typography variant="caption" sx={{ wordBreak: "break-word" }}>
        {value}
      </Typography>
    </Box>
  );
}

export function OutcomeCategoryBadge({ row }: { row: Record<string, unknown> }) {
  const category = resolveCategory(row);
  const summary = resolveSummary(row);
  const color = OUTCOME_COLORS[category] ?? OUTCOME_COLORS.unknown;
  const popoverId = useId();
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const open = Boolean(anchorEl);

  const openPopover = (target: HTMLElement) => setAnchorEl(target);
  const closePopover = () => setAnchorEl(null);

  return (
    <>
      <span
        role="button"
        tabIndex={0}
        aria-describedby={open ? popoverId : undefined}
        className="inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold uppercase text-white cursor-default"
        style={{ backgroundColor: color }}
        onMouseEnter={(e) => openPopover(e.currentTarget)}
        onMouseLeave={closePopover}
        onFocus={(e) => openPopover(e.currentTarget)}
        onBlur={closePopover}
        onClick={(e) => openPopover(e.currentTarget)}
      >
        {category}
      </span>
      <Popover
        id={popoverId}
        open={open}
        anchorEl={anchorEl}
        onClose={closePopover}
        anchorOrigin={{ vertical: "bottom", horizontal: "left" }}
        transformOrigin={{ vertical: "top", horizontal: "left" }}
        disableRestoreFocus
        sx={{ pointerEvents: "none" }}
        slotProps={{
          paper: {
            sx: { pointerEvents: "auto", p: 1.5, maxWidth: 360 },
            onMouseEnter: () => anchorEl && setAnchorEl(anchorEl),
            onMouseLeave: closePopover,
          },
        }}
      >
        <Typography variant="subtitle2" sx={{ mb: 1, textTransform: "capitalize" }}>
          Outcome: {category}
        </Typography>
        <MetadataRow label="Scanner" value={summary.scanner_vendor} />
        <MetadataRow label="Attribution" value={summary.scanner_attribution} />
        <MetadataRow label="CIDR" value={summary.matched_cidr} />
        <MetadataRow label="Classification" value={summary.classification} />
        <MetadataRow label="Priority" value={summary.priority} />
        <MetadataRow label="Frequency" value={summary.frequency_tier} />
        <MetadataRow label="Events today" value={summary.events_today} />
        <MetadataRow
          label="Behavior"
          value={summary.behavior_tags?.length ? summary.behavior_tags.join(", ") : undefined}
        />
        <MetadataRow
          label="Reasons"
          value={summary.reasons?.length ? summary.reasons.join("; ") : undefined}
        />
        <MetadataRow label="Inventory" value={summary.inventory_version != null ? `v${summary.inventory_version}` : undefined} />
      </Popover>
    </>
  );
}

export function getOutcomeSortValue(row: Record<string, unknown>): number {
  const order: Record<string, number> = {
    malicious: 4,
    suspicious: 3,
    unknown: 2,
    benign: 1,
  };
  return order[resolveCategory(row)] ?? 0;
}
