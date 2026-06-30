# STINGAR UI: outcome category column (phase 2)

Patch guide for replacing the color-coded **threat enrichment / effective_severity** column in STINGAR Attack Analysis with the scanner-lite **4-category outcome** column and hover metadata.

This repo indexes session documents to `stingar-*` with the fields below. The patch is applied in [`vendor/stingar-ui/`](../vendor/stingar-ui/) (extracted from `4warned/stingar-ui:v2.3`).

## Target UX

| Current | Target |
|---------|--------|
| Column: `effective_severity` (HIGH/MEDIUM/LOW colors) | Column: `outcome_category` (benign / malicious / suspicious / unknown) |
| Tooltip: threat score / generic signals | Tooltip: scanner vendor, CIDR, behavior tags, priority, reasons, events_today |

One table row = one attack session (`session_id` when present).

## Elasticsearch fields (indexed by scanner-lite)

| Field | Type | UI use |
|-------|------|--------|
| `outcome_category` | keyword | Primary badge column |
| `outcome_summary.scanner_vendor` | keyword | Tooltip |
| `outcome_summary.matched_cidr` | keyword | Tooltip |
| `outcome_summary.behavior_tags` | keyword[] | Tooltip |
| `outcome_summary.priority` | keyword | Tooltip |
| `outcome_summary.reasons` | keyword[] | Tooltip |
| `outcome_summary.events_today` | integer | Tooltip |
| `outcome_summary.inventory_version` | integer | Tooltip (inventory generation) |
| `hp_data.enrichment.scanner_lite` | object | Full drilldown panel |

Legacy field `effective_severity` remains for backward compatibility but should not be the primary column.

## Badge colors

| `outcome_category` | Color |
|--------------------|-------|
| `benign` | `#3d751c` (green) |
| `malicious` | `#bd271e` (red) |
| `suspicious` | `#f5a700` (amber) |
| `unknown` | `#646a73` (gray) |

## Suggested React components

### `OutcomeCategoryBadge`

```tsx
const OUTCOME_COLORS: Record<string, string> = {
  benign: "#3d751c",
  malicious: "#bd271e",
  suspicious: "#f5a700",
  unknown: "#646a73",
};

export function OutcomeCategoryBadge({ category }: { category: string }) {
  const color = OUTCOME_COLORS[category] ?? OUTCOME_COLORS.unknown;
  return (
    <span className="outcome-badge" style={{ backgroundColor: color }}>
      {category}
    </span>
  );
}
```

### `OutcomeMetadataTooltip`

Render on hover over the badge or a dedicated info icon:

- **Scanner:** `outcome_summary.scanner_vendor` or `outcome_summary.scanner_attribution`
- **CIDR:** `outcome_summary.matched_cidr`
- **Classification:** `outcome_summary.classification`
- **Priority:** `outcome_summary.priority`
- **Frequency:** `outcome_summary.frequency_tier`
- **Events today:** `outcome_summary.events_today`
- **Behavior:** `outcome_summary.behavior_tags` (comma-separated)
- **Reasons:** `outcome_summary.reasons` (bullet list)
- **Inventory version:** `outcome_summary.inventory_version`

Fall back to `hp_data.enrichment.scanner_lite` when `outcome_summary` is absent on older documents.

## API / data source

stingarapi should query `stingar-*` and return `_source` including `outcome_category` and `outcome_summary`.

Equivalent HTTP API in this repo:

```bash
curl "http://127.0.0.1:8091/scanner-lite/sessions?q=outcome:suspicious&hours=24"
```

Query aliases: `outcome:`, `outcome_category:`, `category:`, `priority:`, `behavior:`, `scanner:`.

## Kibana interim (shipped in this repo)

Until stingar-ui is patched, use the Attack Analysis Kibana dashboard:

```bash
./scripts/import-stingar-dashboards.sh
```

Dashboard ID: `stingar-attack-analysis-dashboard` — session table with color-mapped `outcome_category` and `outcome_summary.*` columns.

## Implementation (this repo)

Patched files in [`vendor/stingar-ui/`](../vendor/stingar-ui/):

| File | Change |
|------|--------|
| `components/tables/sessions-table.tsx` | SEVERITY → OUTCOME; C2/PAYLOAD/PLAYBOOK columns preserved |
| `components/tables/outcome-category-badge.tsx` | 4-category badge + hover Popover |
| `components/tables/enrichment-columns.ts` | C2/payload/playbook cell helpers |
| `models/sessions.ts` | `outcome_category`, `outcome_summary` in schema |
| `lib/actions.ts` | Pass outcome fields through transform |

Deploy on VM: `./scripts/deploy-stingar-ui-vm.sh`

c2-engine Attack Analysis prototype (`c2-engine/prototype/` on the `c2-engine` branch) may contain table patterns to port. See [C2_ENGINE_INTEGRATION.md](./C2_ENGINE_INTEGRATION.md).

## Verification

1. Ingest a known-scanner IP via webhook or Fluentd (`198.235.24.10` → `benign`).
2. Confirm UI row shows green `benign` badge.
3. Hover shows vendor `Palo Alto Networks Cortex Xpanse` and matched CIDR.
4. PeopleSoft probe IP (`52.29.178.95`) → `suspicious` with `peoplesoft_probe` in behavior tags.
