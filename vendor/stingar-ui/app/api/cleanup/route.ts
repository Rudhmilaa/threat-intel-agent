import { NextRequest, NextResponse } from 'next/server';

const API_HOST = process.env.API_HOST || "http://localhost:8000";
const API_KEY = process.env.API_KEY || "";

export async function POST(request: NextRequest) {
    try {
        const response = await fetch(`${API_HOST}/api/v2/configs/cleanup`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'API-KEY': API_KEY,
            },
            body: JSON.stringify({}),
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Cleanup API error:', response.status, errorText);
            return NextResponse.json(
                { error: `Cleanup failed: ${response.status} ${response.statusText}` },
                { status: response.status }
            );
        }

        const data = await response.json();
        return NextResponse.json(data);
    } catch (error) {
        console.error('Cleanup error:', error);
        return NextResponse.json(
            { error: 'Internal server error during cleanup' },
            { status: 500 }
        );
    }
}
