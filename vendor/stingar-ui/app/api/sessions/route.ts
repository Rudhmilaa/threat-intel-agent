import { NextRequest, NextResponse } from 'next/server';
import { getSessions } from '@/lib/actions';

export async function GET(request: NextRequest) {
    try {
        const { searchParams } = new URL(request.url);

        // Extract query parameters and forward all to backend
        const startAt = searchParams.get('start_at') || '1';
        const rowsPerPage = searchParams.get('rows_per_page') || '100';
        const showData = searchParams.get('show_data') || 'false';
        const srcIp = searchParams.get('src_ip');
        const fromDate = searchParams.get('from_date');
        const toDate = searchParams.get('to_date');

        // Build the API key for the backend
        const params = new URLSearchParams({
            start_at: startAt,
            rows_per_page: rowsPerPage,
            show_data: showData,
        });
        if (srcIp) {
            params.set('src_ip', srcIp);
        }
        if (fromDate) {
            params.set('from_date', fromDate);
        }
        if (toDate) {
            params.set('to_date', toDate);
        }
        const apiKey = `/sessions?${params.toString()}`;

        // Debug logging (commented out for production)
        // console.log('API Route: Pagination params:', { startAt, rowsPerPage, showData });
        // console.log('API Route: Calling backend with:', apiKey);

        // Call the backend through the actions (which includes API key)
        const result = await getSessions(apiKey);

        // Debug logging (commented out for production)
        // console.log('API Route: Backend returned:', {
        //     dataLength: result?.data?.length,
        //     count: result?.count,
        //     firstSessionId: result?.data?.[0]?.id,
        //     lastSessionId: result?.data?.[result?.data?.length - 1]?.id
        // });

        return NextResponse.json(result);

    } catch (error) {
        console.error('Error fetching sessions:', error);
        return NextResponse.json(
            { error: 'Failed to fetch sessions' },
            { status: 500 }
        );
    }
}
