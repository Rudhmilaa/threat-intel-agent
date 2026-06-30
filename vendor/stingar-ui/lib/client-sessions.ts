// Client-side session functions that call Next.js API routes

export async function getSessionsClient(url: string) {
    try {
        // Add cache control to prevent stale data
        const response = await fetch(url, {
            cache: 'no-cache',
            headers: {
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
        });
        if (!response.ok) {
            throw new Error(`Failed to fetch sessions: ${response.statusText}`);
        }
        return response.json();
    } catch (error) {
        console.error('Error fetching sessions:', error);
        throw error;
    }
}

export async function getSessionClient(url: string) {
    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`Failed to fetch session: ${response.statusText}`);
        }
        return response.json();
    } catch (error) {
        console.error('Error fetching session:', error);
        throw error;
    }
}
