import { NextResponse } from 'next/server';
import { getStoreCategories } from '@/lib/store-actions';

export async function GET() {
    try {
        const result = await getStoreCategories();
        return NextResponse.json(result);
    } catch (error) {
        console.error('Error fetching categories:', error);
        return NextResponse.json(
            { error: 'Failed to fetch categories' },
            { status: 500 }
        );
    }
}
