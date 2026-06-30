/**
 * Compute from_date and to_date for Attack Analysis advanced search.
 * Uses UTC for API consistency.
 */
export function computeDateRange(
  anchorDateStr: string,
  rangePreset: "24h" | "7d"
): { fromDate: string; toDate: string } {
  const anchor = new Date(anchorDateStr + "T12:00:00Z");
  if (isNaN(anchor.getTime())) {
    const today = new Date();
    const todayStr = today.toISOString().slice(0, 10);
    return computeDateRange(todayStr, rangePreset);
  }

  if (rangePreset === "24h") {
    const fromDate = `${anchorDateStr}T00:00:00Z`;
    const toDate = `${anchorDateStr}T23:59:59Z`;
    return { fromDate, toDate };
  }

  const startDate = new Date(anchor);
  startDate.setUTCDate(startDate.getUTCDate() - 6);
  const startStr = startDate.toISOString().slice(0, 10);
  const fromDate = `${startStr}T00:00:00Z`;
  const toDate = `${anchorDateStr}T23:59:59Z`;
  return { fromDate, toDate };
}

export function getTodayDateString(): string {
  return new Date().toISOString().slice(0, 10);
}
