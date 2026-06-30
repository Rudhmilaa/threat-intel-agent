"use client";

import { useState, useEffect, useTransition } from "react";
import { usePageTitle } from "@/lib/hooks/use-page-title";
import { useRouter, useParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import NextLink from "next/link";
import { ArrowLeft } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { FormControlLabel, Radio, RadioGroup } from "@mui/material";
import { getFeed, updateFeed, deleteFeed, type Feed } from "@/lib/mellis-actions";

export default function EditInboundFeedPage() {
  const params = useParams();
  const id = typeof params?.id === "string" ? params.id : "";
  usePageTitle(`Threat Feeds: Edit Feed ${id}`);
  const router = useRouter();
  const [isPending, startTransition] = useTransition();

  const [feed, setFeed] = useState<Feed | null>(null);
  const [feedName, setFeedName] = useState("");
  const [sourceType, setSourceType] = useState("open");
  const [sourceFeed, setSourceFeed] = useState("");
  const [weight, setWeight] = useState("0.5");
  const [pollingInterval, setPollingInterval] = useState("3600");
  const [feedFormat, setFeedFormat] = useState("");
  const [enabled, setEnabled] = useState<"1" | "0">("1");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) {
      setLoading(false);
      return;
    }
    startTransition(async () => {
      try {
        const f = await getFeed(id);
        setFeed(f);
        setFeedName(f.name);
        setSourceType(f.source_type);
        setSourceFeed(f.url ?? "");
        setWeight(String(f.weight));
        setPollingInterval(f.poll_interval != null ? String(f.poll_interval) : "");
        setFeedFormat(f.format ?? "");
        setEnabled(f.enabled ? "1" : "0");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load feed");
      } finally {
        setLoading(false);
      }
    });
  }, [id]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!feedName.trim()) {
      setError("Feed name is required.");
      return;
    }
    startTransition(async () => {
      try {
        await updateFeed(id, {
          name: feedName.trim(),
          source_type: sourceType,
          weight: parseFloat(weight) || 0.5,
          url: sourceFeed.trim() || null,
          poll_interval: pollingInterval ? parseInt(pollingInterval) : null,
          format: feedFormat.trim() || null,
          enabled: parseInt(enabled),
        });
        router.push("/threat-feeds/feeds");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to update feed");
      }
    });
  };

  const handleDelete = () => {
    if (!confirm(`Delete feed "${id}"? This cannot be undone.`)) return;
    startTransition(async () => {
      try {
        await deleteFeed(id);
        router.push("/threat-feeds/feeds");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to delete feed");
      }
    });
  };

  if (loading) {
    return (
      <div className="flex flex-col gap-4 max-w-4xl">
        <NextLink href="/threat-feeds/feeds">
          <Button variant="ghost" size="sm" className="gap-1">
            <ArrowLeft className="h-4 w-4" aria-hidden />
            Back to Inbound feeds
          </Button>
        </NextLink>
        <p className="text-muted-foreground">Loading feed...</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6 max-w-4xl">
      <NextLink href="/threat-feeds/feeds">
        <Button variant="ghost" size="sm" className="gap-1">
          <ArrowLeft className="h-4 w-4" aria-hidden />
          Back to Inbound feeds
        </Button>
      </NextLink>

      <h1 className="text-xl font-bold text-left">
        Threat Feeds: Edit Feed &mdash; {id}
      </h1>

      {error && (
        <p className="text-sm text-destructive" role="alert">{error}</p>
      )}

      {feed && (
        <div className="text-sm text-muted-foreground flex gap-4">
          <span>Last fetch: {feed.last_fetch ?? "never"}</span>
          <span>Status: {feed.last_status ?? "never"}</span>
          <span>Created: {feed.created_at}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="flex flex-col gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Settings</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div>
              <Label>Feed ID</Label>
              <p className="font-mono text-sm text-muted-foreground">{id}</p>
            </div>
            <div>
              <Label htmlFor="feed-name">Feed Name</Label>
              <Input
                id="feed-name"
                value={feedName}
                onChange={(e) => setFeedName(e.target.value)}
                placeholder="e.g. AlienVault OTX"
                aria-required="true"
              />
            </div>
            <div>
              <span className="text-sm font-medium block mb-2">Source Type</span>
              <RadioGroup
                row
                value={sourceType}
                onChange={(_, v) => setSourceType(v)}
                aria-label="Source type"
              >
                <FormControlLabel value="local" control={<Radio />} label="Local" />
                <FormControlLabel value="community" control={<Radio />} label="Community" />
                <FormControlLabel value="commercial" control={<Radio />} label="Commercial" />
                <FormControlLabel value="open" control={<Radio />} label="Open" />
                <FormControlLabel value="custom" control={<Radio />} label="Custom" />
              </RadioGroup>
            </div>
            <div>
              <Label htmlFor="source-feed">Source Feed (URL)</Label>
              <Input
                id="source-feed"
                type="url"
                value={sourceFeed}
                onChange={(e) => setSourceFeed(e.target.value)}
                placeholder="https://..."
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Parameters</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div>
              <Label htmlFor="weight">Weight (0.0 - 1.0)</Label>
              <Input
                id="weight"
                type="number"
                step="0.1"
                min="0"
                max="1"
                value={weight}
                onChange={(e) => setWeight(e.target.value)}
              />
            </div>
            <div>
              <Label htmlFor="polling-interval">Polling Interval (seconds)</Label>
              <Input
                id="polling-interval"
                type="number"
                value={pollingInterval}
                onChange={(e) => setPollingInterval(e.target.value)}
                placeholder="3600"
              />
            </div>
            <div>
              <span className="text-sm font-medium block mb-2">Enabled</span>
              <RadioGroup
                row
                value={enabled}
                onChange={(_, v) => setEnabled(v as "1" | "0")}
                aria-label="Feed enabled"
              >
                <FormControlLabel value="1" control={<Radio />} label="Enabled" />
                <FormControlLabel value="0" control={<Radio />} label="Disabled" />
              </RadioGroup>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Format</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div>
              <Label htmlFor="feed-format">Feed Format</Label>
              <Input
                id="feed-format"
                value={feedFormat}
                onChange={(e) => setFeedFormat(e.target.value)}
                placeholder="csv, json, stix, cif, plaintext"
              />
            </div>
          </CardContent>
        </Card>

        <div className="flex gap-2">
          <Button type="submit" disabled={isPending}>
            {isPending ? "Saving..." : "Save"}
          </Button>
          <NextLink href="/threat-feeds/feeds">
            <Button type="button" variant="outline">Cancel</Button>
          </NextLink>
          <Button
            type="button"
            variant="destructive"
            disabled={isPending}
            onClick={handleDelete}
          >
            Delete Feed
          </Button>
        </div>
      </form>
    </div>
  );
}
