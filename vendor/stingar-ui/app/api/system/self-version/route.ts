import { NextResponse } from 'next/server';

// Per-service "what version am I?" endpoint. Reads STINGAR_VERSION
// baked into this container's image at build time (see
// stingar-ui/Dockerfile and Roadmap/plans/VERSIONING_OVERHAUL_PLAN.md
// phase 5 / P3). Does NOT call apiarist; this is the UI container
// answering on its own. Used by the dashboard to detect version-skew
// between UI and apiarist.
export const dynamic = 'force-dynamic';

export async function GET() {
    const raw = (process.env.STINGAR_VERSION || '').trim();
    return NextResponse.json({
        service: 'stingar-ui',
        version: raw || 'unknown',
        source: raw ? 'env:STINGAR_VERSION' : 'unset',
    });
}
