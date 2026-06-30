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
import { listNeverShare, deleteNeverShareEntry, type NeverShareEntry } from "@/lib/mellis-actions";

export default function BlockListsPage() {
  usePageTitle("Block lists");
  const [search, setSearch] = useState("");
  const [entries, setEntries] = useState<NeverShareEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  const loadEntries = () => {
    startTransition(async () => {
      try {
        const res = await listNeverShare();
        setEntries(res.data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load never-share list");
      } finally {
        setLoading(false);
      }
    });
  };

  useEffect(() => {
    loadEntries();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleDelete = (entry: NeverShareEntry) => {
    if (!confirm(`Delete never-share entry "${entry.value}"?`)) return;
    startTransition(async () => {
      try {
        await deleteNeverShareEntry(entry.id);
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

      <h1 className="text-xl font-bold text-left">Block lists (Never-share)</h1>
      <p className="text-muted-foreground text-sm max-w-2xl">
        Create or edit your institution&apos;s known IP address range to prevent internal IPs from being shared with all members. Entries are excluded from CIF submission and outbound feed sharing.
      </p>

      {error && (
        <p className="text-sm text-destructive" role="alert">{error}</p>
      )}

      <div className="flex flex-wrap items-end gap-4">
        <div className="flex-1 min-w-[200px] max-w-sm">
          <Label htmlFor="blocklist-search" className="sr-only">
            Search by IP/CIDR or label
          </Label>
          <Input
            id="blocklist-search"
            placeholder="Search by IP, CIDR, or label"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search block list entries"
          />
        </div>
        <Button variant="outline" size="default" aria-label="Search">
          <Search className="h-4 w-4 mr-2" aria-hidden />
          Search
        </Button>
        <NextLink href="/block-lists/new">
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
              <TableHead>Reason</TableHead>
              <TableHead>Source</TableHead>
              <TableHead className="w-[100px]">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                  Loading block list...
                </TableCell>
              </TableRow>
            ) : filteredEntries.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-center text-muted-foreground py-8">
                  No block list entries. Add an IP or CIDR range to exclude from sharing.
                </TableCell>
              </TableRow>
            ) : (
              filteredEntries.map((entry) => (
                <TableRow key={entry.id}>
                  <TableCell>{entry.type}</TableCell>
                  <TableCell className="font-mono">{entry.value}</TableCell>
                  <TableCell>{entry.label ?? "\u2014"}</TableCell>
                  <TableCell>{entry.reason ?? "\u2014"}</TableCell>
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
