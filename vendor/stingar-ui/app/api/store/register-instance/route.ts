import { NextRequest, NextResponse } from 'next/server';

// Apiarist API configuration (server-side only)
const APIARIST_API_URL = process.env.API_HOST || "http://localhost:8000";

export async function POST(request: NextRequest) {
    try {
        const body = await request.json();
        
        // Proxy registration request to Apiarist (which proxies to HP App Store)
        const response = await fetch(`${APIARIST_API_URL}/api/v2/store/register-instance`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify(body)
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            return NextResponse.json(
                { error: errorData.detail || errorData.message || 'Registration failed' },
                { status: response.status }
            );
        }

        const data = await response.json();
        return NextResponse.json(data);
    } catch (error) {
        console.error('Error proxying registration request:', error);
        return NextResponse.json(
            { error: 'Failed to register instance' },
            { status: 500 }
        );
    }
}

