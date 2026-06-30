import { NextRequest, NextResponse } from 'next/server';
import { getStoreData } from '@/lib/store-actions';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const { searchParams } = new URL(request.url);
    const userIdentifier = searchParams.get('userIdentifier');

    if (!userIdentifier) {
      return NextResponse.json(
        { error: 'User identifier is required' },
        { status: 400 }
      );
    }

    try {
      const result = await getStoreData(
        `/store/requests/${id}/vote-status?user_identifier=${encodeURIComponent(userIdentifier)}`
      );
      return NextResponse.json(result);
    } catch (error: any) {
      // If it's a 404 (request not found), return 404
      if (error.message && error.message.includes('404')) {
        return NextResponse.json(
          { error: 'Request not found' },
          { status: 404 }
        );
      }
      // Re-throw to be caught by outer catch
      throw error;
    }
  } catch (error: any) {
    console.error('Error checking vote status:', error);
    // Check if it's a client error (404) or server error
    const statusCode = error.message && error.message.includes('404') ? 404 : 500;
    return NextResponse.json(
      { error: error.message || 'Failed to check vote status' },
      { status: statusCode }
    );
  }
}

