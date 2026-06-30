import { NextRequest, NextResponse } from 'next/server';

const API_HOST = process.env.API_HOST || "http://localhost:8000";
const API_KEY = process.env.API_KEY || "";

export async function POST(request: NextRequest) {
    try {
        // Get request body for cleanup parameters
        const body = await request.json().catch(() => ({}));
        
        const response = await fetch(`${API_HOST}/api/v2/store/cleanup-cache`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'API-KEY': API_KEY,
            },
            body: JSON.stringify(body),
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Store cache cleanup API error:', response.status, errorText);
            return NextResponse.json(
                { error: `Store cache cleanup failed: ${response.status} ${response.statusText}` },
                { status: response.status }
            );
        }

        const data = await response.json();
        return NextResponse.json(data);
    } catch (error) {
        console.error('Store cache cleanup error:', error);
        return NextResponse.json(
            { error: 'Internal server error during store cache cleanup' },
            { status: 500 }
        );
    }
}
