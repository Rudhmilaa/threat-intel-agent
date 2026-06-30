"use client";

import { useState, useCallback, useEffect, useMemo } from "react";
import SessionsTable from "@/components/tables/sessions-table";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { getIpFilterError } from "@/lib/ip-validation";
import { computeDateRange, getTodayDateString } from "@/lib/date-range-utils";

export default function Sessions() {
  const [isFilterExpanded, setIsFilterExpanded] = useState(false);
  const [searchInput, setSearchInput] = useState("");
  const [srcIpFilter, setSrcIpFilter] = useState<string | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);

  const [anchorDate, setAnchorDate] = useState(() => getTodayDateString());
  const [rangePreset, setRangePreset] = useState<"24h" | "7d">("24h");
  const [useCustomDateRange, setUseCustomDateRange] = useState(false);

  const { fromDate, toDate } = useMemo(() => {
    if (!useCustomDateRange) return { fromDate: null, toDate: null };
    return computeDateRange(anchorDate, rangePreset);
  }, [useCustomDateRange, anchorDate, rangePreset]);

  const applyFilter = useCallback((value: string) => {
    const trimmed = value.trim();
    if (!trimmed) {
      setSrcIpFilter(null);
      setValidationError(null);
      return;
    }
    const error = getIpFilterError(trimmed);
    if (error) {
      setValidationError(error);
      setSrcIpFilter(null);
    } else {
      setValidationError(null);
      setSrcIpFilter(trimmed);
    }
  }, []);

  useEffect(() => {
    if (!searchInput.trim()) {
      setSrcIpFilter(null);
      setValidationError(null);
      return;
    }
    const error = getIpFilterError(searchInput);
    if (error) {
      setValidationError(error);
      setSrcIpFilter(null);
      return;
    }
    setValidationError(null);
    const timer = setTimeout(() => {
      setSrcIpFilter(searchInput.trim());
    }, 500);
    return () => clearTimeout(timer);
  }, [searchInput]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      applyFilter(searchInput);
    }
  };

  const handleResetDateRange = () => {
    setUseCustomDateRange(false);
    setAnchorDate(getTodayDateString());
    setRangePreset("24h");
  };

  return (
    <div className="flex flex-col h-full w-full overflow-x-hidden max-w-full">
      <div className="flex items-center justify-between relative flex-shrink-0 pb-2">
        <h1 className="text-xl font-bold">Attack Analysis</h1>
        <Button
          type="button"
          onClick={() => setIsFilterExpanded(!isFilterExpanded)}
          variant="default"
          size="sm"
          className="bg-blue-600 hover:bg-blue-700 focus-visible:ring-blue-500"
          aria-label={isFilterExpanded ? "Hide advanced search" : "Show advanced search"}
          aria-expanded={isFilterExpanded}
          aria-controls="advanced-search-panel"
        >
          {isFilterExpanded ? "Hide advanced search" : "Advanced search"}
        </Button>
      </div>

      <div
        id="advanced-search-panel"
        role="region"
        aria-label="Advanced search filters"
        className="grid transition-[grid-template-rows] duration-300 ease-in-out"
        style={{ gridTemplateRows: isFilterExpanded ? "1fr" : "0fr" }}
      >
        <div className="overflow-hidden">
          <div className="flex flex-col gap-4 w-full max-w-2xl pb-6 mb-4">
            <div className="flex flex-col gap-2 p-4 border rounded-md bg-muted/30">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="use-date-range"
                  checked={useCustomDateRange}
                  onChange={(e) => setUseCustomDateRange(e.target.checked)}
                  className="rounded border-input"
                />
                <Label htmlFor="use-date-range" className="text-sm font-medium cursor-pointer">
                  Use custom date range
                </Label>
              </div>
              {useCustomDateRange && (
                <div className="flex flex-wrap items-end gap-4 pt-2">
                  <div className="flex flex-col gap-1.5">
                    <Label htmlFor="anchor-date" className="text-xs">
                      Anchor date
                    </Label>
                    <Input
                      id="anchor-date"
                      type="date"
                      value={anchorDate}
                      onChange={(e) => setAnchorDate(e.target.value)}
                      className="w-40"
                    />
                  </div>
                  <div className="flex flex-col gap-1.5">
                    <Label className="text-xs">Range</Label>
                    <div className="flex gap-2">
                      <Button
                        type="button"
                        variant={rangePreset === "24h" ? "default" : "outline"}
                        size="sm"
                        onClick={() => setRangePreset("24h")}
                      >
                        24 hours
                      </Button>
                      <Button
                        type="button"
                        variant={rangePreset === "7d" ? "default" : "outline"}
                        size="sm"
                        onClick={() => setRangePreset("7d")}
                      >
                        7 days
                      </Button>
                    </div>
                  </div>
                  <Button type="button" variant="ghost" size="sm" onClick={handleResetDateRange}>
                    Reset
                  </Button>
                </div>
              )}
            </div>

            <div className="flex flex-col gap-1.5">
              <Label htmlFor="ip-search" className="text-sm font-medium">
                Filter Source Address by IP or CIDR
              </Label>
              <Input
                id="ip-search"
                type="text"
                placeholder="e.g. 152.32.185.214 or 152.32.185.0/24"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                onKeyDown={handleKeyDown}
                onBlur={() => applyFilter(searchInput)}
                className={validationError ? "border-red-500" : ""}
                aria-invalid={!!validationError}
                aria-describedby={validationError ? "ip-search-error" : undefined}
              />
              {validationError && (
                <span id="ip-search-error" className="text-sm text-red-600">
                  {validationError}
                </span>
              )}
              <p className="text-xs text-muted-foreground">
                Supports /8, /16, /24; /32 matches one IP. {useCustomDateRange ? "Custom date range applied." : "Searches last 24 hours by default."}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="w-full max-w-full overflow-x-auto">
        <SessionsTable
          srcIpFilter={srcIpFilter}
          fromDate={fromDate}
          toDate={toDate}
        />
      </div>
    </div>
  );
}
