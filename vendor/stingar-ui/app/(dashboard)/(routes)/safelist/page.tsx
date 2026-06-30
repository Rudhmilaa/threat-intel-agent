"use client";

import { useState, useEffect, useTransition } from "react";
import { usePageTitle } from "@/lib/hooks/use-page-title";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import NextLink from "next/link";
import { Plus, Search, ArrowLeft, Trash2 } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { listSafelist, deleteSafelistEntry, type SafelistEntry } from "@/lib/mellis-actions";

export default function SafelistPage() {
  usePageTitle("Safelist (Never block list)");
  const [search, setSearch] = useState("");
  const [entries, setEntries] = useState<SafelistEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  const loadEntries = () => {
    startTransition(async () => {
      try {
        const res = await listSafelist();
        setEntries(res.data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load safelist");
      } finally {
        setLoading(false);
      }
    });
  };

  useEffect(() => {
    loadEntries();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleDelete = (entry: SafelistEntry) => {
    if (!confirm(`Delete safelist entry "${entry.value}"?`)) return;
    startTransition(async () => {
      try {
        await deleteSafelistEntry(entry.id);
        setEntries((prev) => prev.filter((e) => e.id !== entry.id));
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to delete entry");
      }
    });
  };

  const filteredEntries = search.trim()
    ? entries.filter(
        (e) =>
          e.value.toLowerCase().includes(search.trim().toLowerCase()) ||
          (e.label?.toLowerCase().includes(search.trim().toLowerCase()) ?? false)
      )
    : entries;

  return (
    <div className="flex flex-col gap-4 max-w-full">
      <div className="flex flex-wrap items-center gap-4">
        <NextLink href="/threat-feeds">
          <Button variant="ghost" size="sm" className="gap-1">
            <ArrowLeft className="h-4 w-4" aria-hidden />
            Back to Threat Feeds
          </Button>
        </NextLink>
      </div>

      <h1 className="text-xl font-bold text-left">Safelist (Never block list)</h1>
      <p className="text-muted-foreground text-sm max-w-2xl">
        IPs and ranges that should never be blocked or included in threat feeds. These addresses are always allowed and will not be reported as indicators. Use for trusted infrastructure (e.g. monitoring, scanners, partner networks).
      </p>

      {error && (
        <p className="text-sm text-destructive" role="alert">{error}</p>
      )}

      <div className="flex flex-wrap items-end gap-4">
        <div className="flex-1 min-w-[200px] max-w-sm">
          <Label htmlFor="safelist-search" className="sr-only">
            Search by IP/CIDR or label
          </Label>
          <Input
            id="safelist-search"
            placeholder="Search by IP, CIDR, or label"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search safelist entries"
          />
        </div>
        <Button variant="outline" size="default" aria-label="Search">
          <Search className="h-4 w-4 mr-2" aria-hidden />
          Search
        </Button>
        <NextLink href="/safelist/new">
          <Button variant="default">
            <Plus className="h-4 w-4 mr-2" aria-hidden />
            Add entry
          </Button>
        </NextLink>
      </div>

      <div className="border rounded-md overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Type</TableHead>
              <TableHead>IP / CIDR</TableHead>
              <TableHead>Label</TableHead>
              <TableHead>Source</TableHead>
              <TableHead className="w-[100px]">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                  Loading safelist...
                </TableCell>
              </TableRow>
            ) : filteredEntries.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} className="text-center text-muted-foreground py-8">
                  No safelist entries. Add an IP or CIDR range that should never be blocked.
                </TableCell>
              </TableRow>
            ) : (
              filteredEntries.map((entry) => (
                <TableRow key={entry.id}>
                  <TableCell>{entry.type}</TableCell>
                  <TableCell className="font-mono">{entry.value}</TableCell>
                  <TableCell>{entry.label ?? "\u2014"}</TableCell>
                  <TableCell>{entry.source}</TableCell>
                  <TableCell>
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-label={`Delete ${entry.value}`}
                      disabled={isPending}
                      onClick={() => handleDelete(entry)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
