import { NextRequest, NextResponse } from 'next/server';
import { installStoreHoneypot } from '@/lib/store-actions';

export async function POST(request: NextRequest) {
    try {
        const body = await request.json();
        const { honeypotId, installationData } = body;

        if (!honeypotId) {
            return NextResponse.json(
                { error: 'Honeypot ID is required' },
                { status: 400 }
            );
        }

        const result = await installStoreHoneypot(honeypotId, installationData);

        return NextResponse.json(result);
    } catch (error) {
        console.error('Error installing honeypot:', error);
        return NextResponse.json(
            { error: 'Failed to install honeypot' },
            { status: 500 }
        );
    }
}
