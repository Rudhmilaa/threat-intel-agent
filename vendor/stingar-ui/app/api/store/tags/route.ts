import { NextResponse } from 'next/server';
import { getStoreTags } from '@/lib/store-actions';

export async function GET() {
    try {
        const result = await getStoreTags();
        return NextResponse.json(result);
    } catch (error) {
        console.error('Error fetching tags:', error);
        return NextResponse.json(
            { error: 'Failed to fetch tags' },
            { status: 500 }
        );
    }
}
