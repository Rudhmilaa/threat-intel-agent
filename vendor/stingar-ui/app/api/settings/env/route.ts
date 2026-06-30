import { NextRequest, NextResponse } from 'next/server';

// Apiarist API configuration (server-side only)
// Normalize API_HOST by removing trailing slash if present
const API_HOST_RAW = process.env.API_HOST || "http://localhost:8000";
const APIARIST_API_URL = API_HOST_RAW.replace(/\/+$/, ''); // Remove trailing slashes
const API_KEY = process.env.API_KEY || "";

export async function GET(request: NextRequest) {
    const maxRetries = 3;
    const retryDelay = 1000; // 1 second
    
    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            const response = await fetch(`${APIARIST_API_URL}/api/v2/settings/env`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    'API-KEY': API_KEY,
                },
                cache: 'no-store',
                signal: AbortSignal.timeout(10000), // 10 second timeout
            });

            if (!response.ok) {
                // If 401 and not last attempt, retry (might be Apiarist startup issue)
                if (response.status === 401 && attempt < maxRetries - 1) {
                    await new Promise(resolve => setTimeout(resolve, retryDelay * (attempt + 1)));
                    continue;
                }
                
                const errorText = await response.text();
                if (attempt === maxRetries - 1 || response.status !== 401) {
                    console.error(`Apiarist settings endpoint returned ${response.status} (attempt ${attempt + 1}/${maxRetries}):`, errorText);
                }
                
                return NextResponse.json(
                    { 
                        error: 'Failed to fetch settings',
                        details: response.status === 401 
                            ? 'Apiarist may not be ready yet - this is normal on startup' 
                            : errorText
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
                console.error(`Error proxying settings request to Apiarist (attempt ${attempt + 1}/${maxRetries}):`, error);
            } else {
                await new Promise(resolve => setTimeout(resolve, retryDelay * (attempt + 1)));
                continue;
            }
            
            return NextResponse.json(
                { 
                    error: 'Failed to fetch settings',
                    details: error instanceof Error ? error.message : 'Unknown error - Apiarist may be starting up'
                },
                { status: 503 }
            );
        }
    }
    
    return NextResponse.json(
        { error: 'Failed to fetch settings after retries' },
        { status: 503 }
    );
}

export async function PUT(request: NextRequest) {
    const maxRetries = 2; // Fewer retries for PUT requests
    const retryDelay = 1000;
    
    try {
        const body = await request.json();
        // Apiarist expects variables wrapped in 'variables' key, but we're sending the updates directly
        // So we need to wrap it if it's not already wrapped
        const requestBody = body.variables ? body : { variables: body };
        
        for (let attempt = 0; attempt < maxRetries; attempt++) {
            try {
                const response = await fetch(`${APIARIST_API_URL}/api/v2/settings/env`, {
                    method: 'PUT',
                    headers: {
                        'Accept': 'application/json',
                        'Content-Type': 'application/json',
                        'API-KEY': API_KEY,
                    },
                    body: JSON.stringify(requestBody),
                    cache: 'no-store',
                    signal: AbortSignal.timeout(15000), // 15 second timeout for PUT
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    if (attempt === maxRetries - 1) {
                        console.error(`Apiarist settings update returned ${response.status}:`, errorText);
                    }
                    
                    if (response.status === 401 && attempt < maxRetries - 1) {
                        await new Promise(resolve => setTimeout(resolve, retryDelay * (attempt + 1)));
                        continue;
                    }
                    
                    return NextResponse.json(
                        { 
                            error: 'Failed to update settings',
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
                    console.error(`Error proxying settings update to Apiarist:`, error);
                    return NextResponse.json(
                        { 
                            error: 'Failed to update settings',
                            details: error instanceof Error ? error.message : 'Unknown error'
                        },
                        { status: 500 }
                    );
                }
                
                await new Promise(resolve => setTimeout(resolve, retryDelay * (attempt + 1)));
            }
        }
    } catch (error) {
        console.error('Error parsing request body:', error);
        return NextResponse.json(
            { error: 'Invalid request body' },
            { status: 400 }
        );
    }
    
    return NextResponse.json(
        { error: 'Failed to update settings after retries' },
        { status: 503 }
    );
}

