import { NextRequest, NextResponse } from 'next/server';
import { getStoreHoneypots } from '@/lib/store-actions';

export async function GET(request: NextRequest) {
    try {
        const { searchParams } = new URL(request.url);
        const page = parseInt(searchParams.get('page') || '1');
        const perPage = parseInt(searchParams.get('perPage') || '50');

        // Parse filters from query params
        const filters: any = {};
        const category = searchParams.get('category');
        const hpType = searchParams.get('hpType');
        const status = searchParams.get('status');
        const tags = searchParams.get('tags');
        const minRating = searchParams.get('minRating');

        if (category) filters.category = category;
        if (hpType) filters.hpType = hpType;
        if (status) filters.status = status;
        if (tags) filters.tags = tags;
        if (minRating) filters.minRating = parseInt(minRating);

        const result = await getStoreHoneypots(page, perPage, filters);

        return NextResponse.json(result);
    } catch (error) {
        console.error('Error fetching honeypots:', error);
        return NextResponse.json(
            { error: 'Failed to fetch honeypot data - are you connected to the Internet?' },
            { status: 500 }
        );
    }
}
