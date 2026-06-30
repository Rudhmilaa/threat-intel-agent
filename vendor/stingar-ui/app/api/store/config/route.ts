import { NextRequest, NextResponse } from 'next/server';

// Apiarist API configuration (server-side only)
const APIARIST_API_URL = process.env.API_HOST || "http://localhost:8000";

export async function GET(request: NextRequest) {
    const maxRetries = 3;
    const retryDelay = 1000; // 1 second
    
    for (let attempt = 0; attempt < maxRetries; attempt++) {
        try {
            // Proxy config request to Apiarist
            // Note: This endpoint should be exempt from auth in Apiarist
            const response = await fetch(`${APIARIST_API_URL}/api/v2/store/config`, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                },
                // Don't cache this request - we want fresh config
                cache: 'no-store',
                // Add timeout to avoid hanging
                signal: AbortSignal.timeout(5000), // 5 second timeout
            });

            if (!response.ok) {
                const errorText = await response.text();
                
                // If 401 and not last attempt, retry (might be Apiarist startup issue)
                if (response.status === 401 && attempt < maxRetries - 1) {
                    // Wait before retrying (exponential backoff)
                    await new Promise(resolve => setTimeout(resolve, retryDelay * (attempt + 1)));
                    continue; // Retry
                }
                
                // Log error only on final attempt or non-401 errors
                if (attempt === maxRetries - 1 || response.status !== 401) {
                    console.error(`Apiarist config endpoint returned ${response.status} (attempt ${attempt + 1}/${maxRetries}):`, errorText);
                }
                
                return NextResponse.json(
                    { 
                        error: 'Failed to fetch config',
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
            // Handle timeout or connection errors
            if (error instanceof Error && error.name === 'AbortError') {
                if (attempt < maxRetries - 1) {
                    // Retry on timeout
                    await new Promise(resolve => setTimeout(resolve, retryDelay * (attempt + 1)));
                    continue;
                }
            }
            
            // Log error only on final attempt
            if (attempt === maxRetries - 1) {
                console.error(`Error proxying config request to Apiarist (attempt ${attempt + 1}/${maxRetries}):`, error);
            } else {
                // Silently retry on connection errors (Apiarist might be starting up)
                await new Promise(resolve => setTimeout(resolve, retryDelay * (attempt + 1)));
                continue;
            }
            
            return NextResponse.json(
                { 
                    error: 'Failed to fetch config',
                    details: error instanceof Error ? error.message : 'Unknown error - Apiarist may be starting up'
                },
                { status: 503 } // Service Unavailable
            );
        }
    }
    
    // Should never reach here, but just in case
    return NextResponse.json(
        { error: 'Failed to fetch config after retries' },
        { status: 503 }
    );
}

