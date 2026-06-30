import { NextResponse } from 'next/server';
import { checkStoreAvailability } from '@/lib/store-actions';

export async function GET() {
    try {
        const isAvailable = await checkStoreAvailability();
        return NextResponse.json({ isAvailable });
    } catch (error) {
        console.error('Error checking store availability:', error);
        return NextResponse.json(
            { isAvailable: false, error: 'Failed to check availability' },
            { status: 500 }
        );
    }
}
