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
import { listFeeds, deleteFeed, type Feed } from "@/lib/mellis-actions";

export default function InboundFeedsListPage() {
  usePageTitle("Threat Feeds: Manage Inbound feeds");
  const [searchName, setSearchName] = useState("");
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  const loadFeeds = () => {
    startTransition(async () => {
      try {
        const res = await listFeeds();
        setFeeds(res.data);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load feeds");
      } finally {
        setLoading(false);
      }
    });
  };

  useEffect(() => {
    loadFeeds();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const handleDelete = (id: string) => {
    if (!confirm(`Delete feed "${id}"? This cannot be undone.`)) return;
    startTransition(async () => {
      try {
        await deleteFeed(id);
        setFeeds((prev) => prev.filter((f) => f.id !== id));
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to delete feed");
      }
    });
  };

  const filteredFeeds = searchName.trim()
    ? feeds.filter((f) => f.name.toLowerCase().includes(searchName.trim().toLowerCase()))
    : feeds;

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

      <h1 className="text-xl font-bold text-left">Threat Feeds: Manage Inbound feeds</h1>

      {error && (
        <p className="text-sm text-destructive" role="alert">{error}</p>
      )}

      <div className="flex flex-wrap items-end gap-4">
        <div className="flex-1 min-w-[200px] max-w-sm">
          <Label htmlFor="feed-search" className="sr-only">
            Search by feed name
          </Label>
          <Input
            id="feed-search"
            placeholder="NAME"
            value={searchName}
            onChange={(e) => setSearchName(e.target.value)}
            aria-label="Search feeds by name"
          />
        </div>
        <Button variant="outline" size="default" aria-label="Search">
          <Search className="h-4 w-4 mr-2" aria-hidden />
          Search
        </Button>
        <NextLink href="/threat-feeds/feeds/new">
          <Button variant="default">
            <Plus className="h-4 w-4 mr-2" aria-hidden />
            Add New Feed
          </Button>
        </NextLink>
      </div>

      <div className="border rounded-md overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>ID</TableHead>
              <TableHead>ENABLED</TableHead>
              <TableHead>TYPE</TableHead>
              <TableHead>NAME</TableHead>
              <TableHead>FORMAT</TableHead>
              <TableHead>STATUS</TableHead>
              <TableHead className="w-[120px]">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                  Loading feeds...
                </TableCell>
              </TableRow>
            ) : filteredFeeds.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center text-muted-foreground py-8">
                  No inbound feeds configured. Add a feed to get started.
                </TableCell>
              </TableRow>
            ) : (
              filteredFeeds.map((feed) => (
                <TableRow key={feed.id}>
                  <TableCell className="font-mono">{feed.id}</TableCell>
                  <TableCell>{feed.enabled ? "TRUE" : "FALSE"}</TableCell>
                  <TableCell>{feed.source_type}</TableCell>
                  <TableCell>{feed.name}</TableCell>
                  <TableCell>{feed.format ?? "—"}</TableCell>
                  <TableCell>{feed.last_status ?? "never"}</TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      <NextLink href={`/threat-feeds/feeds/${feed.id}`}>
                        <Button variant="ghost" size="sm">Edit</Button>
                      </NextLink>
                      <Button
                        variant="ghost"
                        size="sm"
                        aria-label={`Delete ${feed.name}`}
                        disabled={isPending}
                        onClick={() => handleDelete(feed.id)}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
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
