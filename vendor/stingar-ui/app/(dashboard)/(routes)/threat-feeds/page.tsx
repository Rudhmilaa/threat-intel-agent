"use client";

import { usePageTitle } from "@/lib/hooks/use-page-title";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import NextLink from "next/link";
import {
  Rss,
  ShieldCheck,
  FileOutput,
  CheckCircle,
  Activity,
  Database,
  Shield,
  BarChart3,
  RefreshCw,
  AlertTriangle,
  Layers,
} from "lucide-react";
import { useEffect, useState, useCallback } from "react";
import type { MellisStats, MellisStatsHistory } from "@/lib/mellis-actions";
import { getMellisStats, getMellisStatsHistory } from "@/lib/mellis-actions";

const POLL_INTERVAL = 30_000;

function formatUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

const TYPE_COLORS: Record<string, string> = {
  ipv4: "#3b82f6",
  ipv6: "#6366f1",
  domain: "#10b981",
  url: "#f59e0b",
  sha256: "#ef4444",
  md5: "#8b5cf6",
  sha1: "#ec4899",
  email: "#06b6d4",
};

const SCORE_COLORS = ["#22c55e", "#84cc16", "#eab308", "#f97316", "#ef4444"];

function HorizontalBar({ items, colorMap }: { items: { label: string; value: number }[]; colorMap: Record<string, string> }) {
  const total = items.reduce((s, i) => s + i.value, 0);
  if (total === 0) return <div className="text-sm text-muted-foreground">No data</div>;

  return (
    <div className="space-y-2">
      <div className="flex h-4 w-full rounded-full overflow-hidden bg-muted">
        {items.map((item) => {
          const pct = (item.value / total) * 100;
          if (pct < 0.5) return null;
          return (
            <div
              key={item.label}
              style={{ width: `${pct}%`, backgroundColor: colorMap[item.label] || "#9ca3af" }}
              title={`${item.label}: ${item.value} (${pct.toFixed(1)}%)`}
            />
          );
        })}
      </div>
      <div className="flex flex-wrap gap-3 text-xs">
        {items.map((item) => (
          <div key={item.label} className="flex items-center gap-1.5">
            <div
              className="w-2.5 h-2.5 rounded-full shrink-0"
              style={{ backgroundColor: colorMap[item.label] || "#9ca3af" }}
            />
            <span className="text-muted-foreground">{item.label}</span>
            <span className="font-medium">{formatNumber(item.value)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function ScoreBar({ items }: { items: { label: string; value: number }[] }) {
  const total = items.reduce((s, i) => s + i.value, 0);
  if (total === 0) return <div className="text-sm text-muted-foreground">No data</div>;

  const maxVal = Math.max(...items.map((i) => i.value));

  return (
    <div className="space-y-1.5">
      {items.map((item, idx) => (
        <div key={item.label} className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground w-14 text-right shrink-0">{item.label}</span>
          <div className="flex-1 h-5 bg-muted rounded-sm overflow-hidden">
            <div
              className="h-full rounded-sm transition-all"
              style={{
                width: maxVal > 0 ? `${(item.value / maxVal) * 100}%` : "0%",
                backgroundColor: SCORE_COLORS[idx] || "#9ca3af",
              }}
            />
          </div>
          <span className="text-xs font-medium w-12 text-right">{formatNumber(item.value)}</span>
        </div>
      ))}
    </div>
  );
}

function Sparkline({ points, height = 40 }: { points: number[]; height?: number }) {
  if (points.length < 2) return <div className="text-xs text-muted-foreground">Collecting data...</div>;

  const max = Math.max(...points);
  const min = Math.min(...points);
  const range = max - min || 1;
  const width = 200;
  const padding = 2;

  const pathPoints = points.map((val, i) => {
    const x = padding + (i / (points.length - 1)) * (width - 2 * padding);
    const y = padding + (1 - (val - min) / range) * (height - 2 * padding);
    return `${x},${y}`;
  });

  const d = `M ${pathPoints.join(" L ")}`;

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full" style={{ maxWidth: width }}>
      <path d={d} fill="none" stroke="#3b82f6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function StatCard({
  label,
  value,
  icon: Icon,
  subtitle,
  variant,
}: {
  label: string;
  value: string;
  icon: React.ElementType;
  subtitle?: string;
  variant?: "default" | "warning";
}) {
  return (
    <Card className={variant === "warning" ? "border-amber-300 bg-amber-50/50" : ""}>
      <CardContent className="p-4">
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <p className="text-sm text-muted-foreground">{label}</p>
            <p className="text-2xl font-bold tracking-tight">{value}</p>
            {subtitle && <p className="text-xs text-muted-foreground">{subtitle}</p>}
          </div>
          <Icon className="h-5 w-5 text-muted-foreground shrink-0" />
        </div>
      </CardContent>
    </Card>
  );
}

function FeedStatusBadge({ status }: { status: string | null }) {
  if (!status) return <Badge variant="outline">never</Badge>;
  if (status === "ok") return <Badge className="bg-green-100 text-green-800 border-green-300">ok</Badge>;
  if (status === "error") return <Badge variant="destructive">error</Badge>;
  return <Badge variant="secondary">{status}</Badge>;
}

export default function ThreatFeedsPage() {
  usePageTitle("Threat Feeds");

  const [stats, setStats] = useState<MellisStats | null>(null);
  const [history, setHistory] = useState<MellisStatsHistory | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const [s, h] = await Promise.all([
        getMellisStats(),
        getMellisStatsHistory("24h"),
      ]);
      setStats(s);
      setHistory(h);
      setError(null);
      setLastUpdated(new Date());
    } catch (e: any) {
      setError(e.message || "Failed to fetch statistics");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, POLL_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchData]);

  const feedsWithErrors = (stats?.feeds ?? []).filter((f) => f.last_status === "error");

  return (
    <div className="flex flex-col gap-6 max-w-6xl pb-8">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold">Threat Feeds</h1>
        <div className="flex items-center gap-3">
          {lastUpdated && (
            <span className="text-xs text-muted-foreground">
              Updated {lastUpdated.toLocaleTimeString()}
            </span>
          )}
          <Button variant="outline" size="sm" onClick={fetchData} disabled={loading}>
            <RefreshCw className={`h-4 w-4 mr-1 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <Card className="border-amber-300 bg-amber-50/50">
          <CardContent className="p-4 flex items-center gap-2 text-amber-800">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            <span className="text-sm">
              Could not load statistics from mellis. The feed engine may not be running.
            </span>
          </CardContent>
        </Card>
      )}

      {loading && !stats ? (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <Card key={i}>
              <CardContent className="p-4 space-y-2">
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-8 w-16" />
                <Skeleton className="h-3 w-20" />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : stats ? (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              label="Total IOCs"
              value={formatNumber(stats.indicators.total)}
              icon={Database}
              subtitle={`${formatNumber(stats.indicators.active)} active`}
            />
            <StatCard
              label="Honeypot IOCs"
              value={formatNumber(stats.indicators.local_honeypot)}
              icon={Shield}
              subtitle="Locally observed"
            />
            <StatCard
              label="Active Feeds"
              value={String((stats.feeds ?? []).filter((f) => f.enabled).length)}
              icon={Rss}
              subtitle={`${(stats.feeds ?? []).length} total configured`}
            />
            <StatCard
              label="Expired IOCs"
              value={formatNumber(stats.indicators.expired)}
              icon={Activity}
              subtitle="Past TTL"
            />
            <StatCard
              label="Safelist Entries"
              value={formatNumber(stats.safelist_count)}
              icon={CheckCircle}
            />
            <StatCard
              label="Never-share Entries"
              value={formatNumber(stats.never_share_count)}
              icon={ShieldCheck}
            />
            <StatCard
              label="Output Feeds"
              value={String(stats.output_feed_count)}
              icon={FileOutput}
            />
            <StatCard
              label="Engine Uptime"
              value={formatUptime(stats.engine.uptime_seconds)}
              icon={Activity}
              subtitle={`v${stats.engine.version} | DB ${stats.engine.db_size_mb.toFixed(1)} MB`}
            />
          </div>

          {feedsWithErrors.length > 0 && (
            <Card className="border-red-300 bg-red-50/50">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2 text-red-800">
                  <AlertTriangle className="h-4 w-4" />
                  {feedsWithErrors.length} feed{feedsWithErrors.length > 1 ? "s" : ""} reporting errors
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-0">
                <div className="flex flex-wrap gap-2">
                  {feedsWithErrors.map((f) => (
                    <NextLink key={f.id} href={`/threat-feeds/feeds/${f.id}`}>
                      <Badge variant="destructive" className="cursor-pointer">{f.name}</Badge>
                    </NextLink>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* IOC type breakdown */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <BarChart3 className="h-4 w-4" />
                  IOC Type Breakdown
                </CardTitle>
              </CardHeader>
              <CardContent>
                <HorizontalBar
                  items={(stats.by_type ?? []).map((t) => ({ label: t.type, value: t.count }))}
                  colorMap={TYPE_COLORS}
                />
              </CardContent>
            </Card>

            {/* Score distribution */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <BarChart3 className="h-4 w-4" />
                  Score Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ScoreBar
                  items={(stats.score_distribution ?? []).map((s) => ({ label: s.range, value: s.count }))}
                />
              </CardContent>
            </Card>

            {/* IOC growth sparkline */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  IOC Growth (24h)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <Sparkline points={(history?.points ?? []).map((p) => p.total_indicators)} />
              </CardContent>
            </Card>

            {/* Overlap summary */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Layers className="h-4 w-4" />
                  Feed Overlap (top pairs)
                </CardTitle>
              </CardHeader>
              <CardContent>
                {(stats.overlap ?? []).length === 0 ? (
                  <p className="text-sm text-muted-foreground">No overlap data available yet.</p>
                ) : (
                  <div className="space-y-2">
                    {(stats.overlap ?? []).slice(0, 5).map((o, i) => (
                      <div key={i} className="flex items-center justify-between text-sm">
                        <span className="text-muted-foreground">
                          {o.feed_a} / {o.feed_b}
                        </span>
                        <div className="flex items-center gap-2">
                          <span className="font-medium">{formatNumber(o.shared_count)} shared</span>
                          <Badge variant="outline">{o.overlap_pct.toFixed(1)}%</Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Feed status table */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <Rss className="h-4 w-4" />
                Feed Status
              </CardTitle>
              <CardDescription>All configured threat feeds and their current state.</CardDescription>
            </CardHeader>
            <CardContent>
              {(stats.feeds ?? []).length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No feeds configured.{" "}
                  <NextLink href="/threat-feeds/feeds/new" className="underline text-primary">
                    Add one
                  </NextLink>
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Feed</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead className="text-right">IOCs</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Last Fetch</TableHead>
                      <TableHead className="text-right">Enabled</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(stats.feeds ?? []).map((feed) => (
                      <TableRow key={feed.id}>
                        <TableCell>
                          <NextLink
                            href={`/threat-feeds/feeds/${feed.id}`}
                            className="font-medium text-primary hover:underline"
                          >
                            {feed.name}
                          </NextLink>
                        </TableCell>
                        <TableCell>
                          <Badge variant="secondary">{feed.source_type}</Badge>
                        </TableCell>
                        <TableCell className="text-right font-mono">
                          {formatNumber(feed.indicator_count)}
                        </TableCell>
                        <TableCell>
                          <FeedStatusBadge status={feed.last_status} />
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {feed.last_fetch
                            ? new Date(feed.last_fetch).toLocaleString()
                            : "never"}
                        </TableCell>
                        <TableCell className="text-right">
                          {feed.enabled ? (
                            <span className="inline-block w-2 h-2 rounded-full bg-green-500" title="Enabled" />
                          ) : (
                            <span className="inline-block w-2 h-2 rounded-full bg-gray-300" title="Disabled" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </>
      ) : null}

      {/* Navigation cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Rss className="h-5 w-5" aria-hidden />
              Manage Threat Feeds
            </CardTitle>
            <CardDescription>Add and manage inbound threat feeds.</CardDescription>
          </CardHeader>
          <CardContent>
            <NextLink href="/threat-feeds/feeds">
              <Button variant="default">Manage Feeds</Button>
            </NextLink>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <ShieldCheck className="h-5 w-5" aria-hidden />
              Block Lists (Never Share)
            </CardTitle>
            <CardDescription>
              Prevent internal IPs from being shared with the community.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <NextLink href="/block-lists">
              <Button variant="default">Manage Block Lists</Button>
            </NextLink>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <CheckCircle className="h-5 w-5" aria-hidden />
              Safelist (Never Block)
            </CardTitle>
            <CardDescription>
              IPs and ranges that should never appear in threat feeds.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <NextLink href="/safelist">
              <Button variant="default">Manage Safelist</Button>
            </NextLink>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <FileOutput className="h-5 w-5" aria-hidden />
              Export / Output Feeds
            </CardTitle>
            <CardDescription>
              Filter or format outbound feed parameters for Firewall/IDP.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <NextLink href="/threat-feeds/export">
              <Button variant="default">Manage Exports</Button>
            </NextLink>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
