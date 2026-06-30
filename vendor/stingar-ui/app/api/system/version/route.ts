import { NextResponse } from 'next/server';
import { getSystemVersion } from '@/lib/update-actions';

export async function GET() {
    try {
        const versionInfo = await getSystemVersion();
        return NextResponse.json(versionInfo);
    } catch (error) {
        // Check if it's an authentication error (401)
        if (error instanceof Error && error.message.includes('401')) {
            // Return 401 instead of 500 for auth errors
            return NextResponse.json(
                {
                    error: 'Authentication failed',
                    details: 'API_KEY may be missing or invalid. This is normal if the backend is not configured.'
                },
                { status: 401 }
            );
        }

        // Log other errors but don't spam console in development
        const errorMessage = error instanceof Error ? error.message : String(error);
        if (process.env.NODE_ENV === 'production' || !errorMessage.includes('401')) {
            console.error('Error fetching system version:', error);
        }

        return NextResponse.json(
            {
                error: 'Failed to fetch system version',
                details: error instanceof Error ? error.message : 'Unknown error'
            },
            { status: 500 }
        );
    }
}
