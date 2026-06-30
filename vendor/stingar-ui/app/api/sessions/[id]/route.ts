import { NextRequest, NextResponse } from 'next/server';
import { getSession } from '@/lib/actions';

export async function GET(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    try {
        const { id: sessionId } = await params;

        if (!sessionId) {
            return NextResponse.json(
                { error: 'Session ID is required' },
                { status: 400 }
            );
        }

        // Build the API key for the backend
        const apiKey = `/sessions/${sessionId}`;

        // Call the backend through the actions (which includes API key)
        const result = await getSession(apiKey);

        return NextResponse.json(result);
    } catch (error) {
        console.error('Error fetching session:', error);
        return NextResponse.json(
            { error: 'Failed to fetch session' },
            { status: 500 }
        );
    }
}
