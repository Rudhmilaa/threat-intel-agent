'use server';

import { readFileSync } from "fs";

// --- Types ---

export type Feed = {
    id: string;
    name: string;
    source_type: string;
    weight: number;
    url: string | null;
    poll_interval: number | null;
    format: string | null;
    enabled: number;
    last_fetch: string | null;
    last_status: string | null;
    created_at: string;
};

export type SafelistEntry = {
    id: number;
    type: string;
    value: string;
    label: string | null;
    source: string;
    created_at: string;
    updated_at: string;
};

export type NeverShareEntry = {
    id: number;
    type: string;
    value: string;
    label: string | null;
    reason: string | null;
    source: string;
    created_at: string;
    updated_at: string;
    created_by: string | null;
};

export type OutputFeed = {
    id: string;
    name: string;
    format: string;
    ioc_types: string | null;
    max_entries: number;
    min_score: number;
    exclude_safelist: number;
    refresh_interval: number;
    include_local_only: number;
    last_generated: string | null;
    cache_path: string | null;
    legacy_filename: string | null;
};

export type PaginatedResponse<T> = {
    data: T[];
    meta: { page: number; per_page: number; total: number };
};

export type MellisHealth = {
    status: string;
    version: string;
    uptime_seconds: number;
    db_size_mb: number;
    indicator_count: number;
    feed_count: number;
    active_goroutines: number;
};

export type IndicatorTotals = {
    total: number;
    active: number;
    expired: number;
    local_honeypot: number;
};

export type TypeBreakdown = {
    type: string;
    count: number;
};

export type SourceBreakdown = {
    source_type: string;
    count: number;
};

export type ScoreDistribution = {
    range: string;
    count: number;
};

export type FeedSummary = {
    id: string;
    name: string;
    source_type: string;
    enabled: number;
    last_fetch: string | null;
    last_status: string | null;
    indicator_count: number;
};

export type OverlapSummary = {
    feed_a: string;
    feed_b: string;
    shared_count: number;
    overlap_pct: number;
};

export type EngineHealth = {
    uptime_seconds: number;
    db_size_mb: number;
    active_goroutines: number;
    version: string;
};

export type MellisStats = {
    timestamp: string;
    indicators: IndicatorTotals;
    by_type: TypeBreakdown[];
    by_source: SourceBreakdown[];
    score_distribution: ScoreDistribution[];
    feeds: FeedSummary[];
    overlap: OverlapSummary[];
    safelist_count: number;
    never_share_count: number;
    output_feed_count: number;
    engine: EngineHealth;
};

export type HistoryPoint = {
    recorded_at: string;
    total_indicators: number;
    active_indicators: number;
    expired_indicators: number;
    new_since_last: number;
    expired_since_last: number;
    honeypot_new: number;
    safelisted: number;
};

export type MellisStatsHistory = {
    period: string;
    points: HistoryPoint[];
};

// --- Internal config ---

const MELLIS_HOST_RAW = process.env.MELLIS_HOST || 'http://mellis:8100';
const MELLIS_HOST = MELLIS_HOST_RAW.replace(/\/+$/, '');
const MELLIS_URL = `${MELLIS_HOST}/api/v2`;

function getApiKey(): string {
    const fromEnv = process.env.API_KEY;
    if (fromEnv) return fromEnv;
    const envPath = process.env.STINGAR_ENV_PATH || '/app/stingar.env';
    try {
        const content = readFileSync(envPath, 'utf8');
        const m = content.match(/^API_KEY=(.*)$/m);
        return m ? m[1].trim() : '';
    } catch {
        return '';
    }
}

function authHeaders(): Record<string, string> {
    return {
        "Authorization": `STINGAR-TOKEN ${getApiKey()}`,
        "Content-Type": "application/json",
    };
}

// --- Internal helpers ---

async function mellisGetNoAuth(url: string): Promise<any> {
    const resp = await fetch(url, { cache: "no-cache" });
    if (!resp.ok) {
        const body = await resp.text();
        throw new Error(`GET ${url} failed: ${resp.status} ${resp.statusText}: ${body}`);
    }
    return resp.json();
}

async function mellisGet(path: string): Promise<any> {
    const url = `${MELLIS_URL}${path}`;
    const resp = await fetch(url, {
        cache: "no-cache",
        headers: authHeaders(),
    });
    if (!resp.ok) {
        const body = await resp.text();
        throw new Error(`GET ${path} failed: ${resp.status} ${resp.statusText}: ${body}`);
    }
    return resp.json();
}

async function mellisPost(path: string, data: any): Promise<any> {
    const url = `${MELLIS_URL}${path}`;
    const resp = await fetch(url, {
        method: "POST",
        cache: "no-cache",
        headers: authHeaders(),
        body: JSON.stringify(data),
    });
    if (!resp.ok) {
        const body = await resp.text();
        throw new Error(`POST ${path} failed: ${resp.status} ${resp.statusText}: ${body}`);
    }
    return resp.json();
}

async function mellisPut(path: string, data: any): Promise<any> {
    const url = `${MELLIS_URL}${path}`;
    const resp = await fetch(url, {
        method: "PUT",
        cache: "no-cache",
        headers: authHeaders(),
        body: JSON.stringify(data),
    });
    if (!resp.ok) {
        const body = await resp.text();
        throw new Error(`PUT ${path} failed: ${resp.status} ${resp.statusText}: ${body}`);
    }
    return resp.json();
}

async function mellisDelete(path: string): Promise<void> {
    const url = `${MELLIS_URL}${path}`;
    const resp = await fetch(url, {
        method: "DELETE",
        cache: "no-cache",
        headers: authHeaders(),
    });
    if (resp.status === 204) return;
    if (!resp.ok) {
        const body = await resp.text();
        throw new Error(`DELETE ${path} failed: ${resp.status} ${resp.statusText}: ${body}`);
    }
}

// --- Exported actions: Health ---

export async function getMellisHealth(): Promise<MellisHealth> {
    return mellisGetNoAuth(`${MELLIS_HOST}/health`);
}

// --- Exported actions: Feeds ---

export async function listFeeds(params?: {
    page?: number;
    per_page?: number;
}): Promise<PaginatedResponse<Feed>> {
    const search = new URLSearchParams();
    if (params?.page != null) search.set("page", String(params.page));
    if (params?.per_page != null) search.set("per_page", String(params.per_page));
    const qs = search.toString();
    return mellisGet(`/feeds${qs ? '?' + qs : ''}`);
}

export async function getFeed(id: string): Promise<Feed> {
    return mellisGet(`/feeds/${id}`);
}

export async function createFeed(data: Partial<Feed>): Promise<Feed> {
    return mellisPost("/feeds", data);
}

export async function updateFeed(id: string, data: Partial<Feed>): Promise<Feed> {
    return mellisPut(`/feeds/${id}`, data);
}

export async function deleteFeed(id: string): Promise<void> {
    return mellisDelete(`/feeds/${id}`);
}

// --- Exported actions: Safelist ---

export async function listSafelist(params?: {
    page?: number;
    per_page?: number;
}): Promise<PaginatedResponse<SafelistEntry>> {
    const search = new URLSearchParams();
    if (params?.page != null) search.set("page", String(params.page));
    if (params?.per_page != null) search.set("per_page", String(params.per_page));
    const qs = search.toString();
    return mellisGet(`/safelist${qs ? '?' + qs : ''}`);
}

export async function createSafelistEntry(
    data: Omit<SafelistEntry, 'id' | 'created_at' | 'updated_at'>
): Promise<SafelistEntry> {
    return mellisPost("/safelist", data);
}

export async function updateSafelistEntry(
    id: number,
    data: Partial<Omit<SafelistEntry, 'id' | 'created_at' | 'updated_at'>>
): Promise<SafelistEntry> {
    return mellisPut(`/safelist/${id}`, data);
}

export async function deleteSafelistEntry(id: number): Promise<void> {
    return mellisDelete(`/safelist/${id}`);
}

// --- Exported actions: Never-share ---

export async function listNeverShare(params?: {
    page?: number;
    per_page?: number;
}): Promise<PaginatedResponse<NeverShareEntry>> {
    const search = new URLSearchParams();
    if (params?.page != null) search.set("page", String(params.page));
    if (params?.per_page != null) search.set("per_page", String(params.per_page));
    const qs = search.toString();
    return mellisGet(`/never-share${qs ? '?' + qs : ''}`);
}

export async function createNeverShareEntry(
    data: Omit<NeverShareEntry, 'id' | 'created_at' | 'updated_at'>
): Promise<NeverShareEntry> {
    return mellisPost("/never-share", data);
}

export async function updateNeverShareEntry(
    id: number,
    data: Partial<Omit<NeverShareEntry, 'id' | 'created_at' | 'updated_at'>>
): Promise<NeverShareEntry> {
    return mellisPut(`/never-share/${id}`, data);
}

export async function deleteNeverShareEntry(id: number): Promise<void> {
    return mellisDelete(`/never-share/${id}`);
}

// --- Exported actions: Output feeds ---

export async function listOutputFeeds(): Promise<PaginatedResponse<OutputFeed>> {
    return mellisGet("/output-feeds");
}

// --- Exported actions: Statistics ---

export async function getMellisStats(): Promise<MellisStats> {
    return mellisGet("/stats");
}

export async function getMellisStatsHistory(
    period?: "1h" | "6h" | "24h" | "7d" | "30d"
): Promise<MellisStatsHistory> {
    const qs = period ? `?period=${period}` : '';
    return mellisGet(`/stats/history${qs}`);
}
