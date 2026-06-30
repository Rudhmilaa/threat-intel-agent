import { NextRequest, NextResponse } from 'next/server';

// Apiarist API configuration (server-side only)
const APIARIST_API_URL = process.env.API_HOST || "http://localhost:8000";
const API_KEY = process.env.API_KEY || "";

export async function GET(
    request: NextRequest,
    { params }: { params: Promise<{ variable: string }> }
) {
    const maxRetries = 3;
    const retryDelay = 1000;
    
    const { variable: variableName } = await params;
    
    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            const response = await fetch(`${APIARIST_API_URL}/api/v2/settings/env/${variableName}`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'API-KEY': API_KEY,
                },
                cache: 'no-store',
                signal: AbortSignal.timeout(10000),
            });

            if (!response.ok) {
                if (response.status === 401 && attempt < maxRetries - 1) {
                    await new Promise(resolve => setTimeout(resolve, retryDelay * (attempt + 1)));
                    continue;
                }
                
                const errorText = await response.text();
                if (attempt === maxRetries - 1 || response.status !== 401) {
                    console.error(`Apiarist settings variable endpoint returned ${response.status}:`, errorText);
                }
                
                return NextResponse.json(
                    { 
                        error: 'Failed to fetch variable',
                        details: errorText
                    },
                    { status: response.status }
                );
            }

            const data = await response.json();
            return NextResponse.json(data);
        } catch (error) {
            if (error instanceof Error && error.name === 'AbortError') {
                if (attempt < maxRetries - 1) {
                    await new Promise(resolve => setTimeout(resolve, retryDelay * (attempt + 1)));
                    continue;
                }
            }
            
            if (attempt === maxRetries - 1) {
                console.error(`Error proxying variable request to Apiarist:`, error);
            } else {
                await new Promise(resolve => setTimeout(resolve, retryDelay * (attempt + 1)));
                continue;
            }
            
            return NextResponse.json(
                { 
                    error: 'Failed to fetch variable',
                    details: error instanceof Error ? error.message : 'Unknown error'
                },
                { status: 503 }
            );
        }
    }
    
    return NextResponse.json(
        { error: 'Failed to fetch variable after retries' },
        { status: 503 }
    );
}

