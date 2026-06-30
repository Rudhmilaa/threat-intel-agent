import { NextRequest, NextResponse } from 'next/server';
import { postStoreData, deleteStoreData } from '@/lib/store-actions';

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const { userIdentifier } = await request.json();

    if (!userIdentifier) {
      return NextResponse.json(
        { error: 'User identifier is required' },
        { status: 400 }
      );
    }

    // The backend expects user_identifier in the body
    // Use postStoreData which will convert camelCase to snake_case
    try {
      const result = await postStoreData(
        `/store/requests/${id}/vote`,
        { userIdentifier: userIdentifier }
      );
      return NextResponse.json(result);
    } catch (error: any) {
      // If it's a 400 error (already voted), return 400 instead of 500
      if (error.message && error.message.includes('already voted')) {
        return NextResponse.json(
          { error: error.message },
          { status: 400 }
        );
      }
      // Re-throw to be caught by outer catch
      throw error;
    }
  } catch (error: any) {
    console.error('Error voting on request:', error);
    // Check if it's a client error (400, 401, etc.) or server error
    const statusCode = error.message && (
      error.message.includes('already voted') ||
      error.message.includes('Request failed with status 400')
    ) ? 400 : 500;
    return NextResponse.json(
      { error: error.message || 'Failed to vote' },
      { status: statusCode }
    );
  }
}

export async function DELETE(
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

    const result = await deleteStoreData(
      `/store/requests/${id}/vote?user_identifier=${userIdentifier}`
    );

    return NextResponse.json(result);
  } catch (error: any) {
    console.error('Error removing vote:', error);
    return NextResponse.json(
      { error: error.message || 'Failed to remove vote' },
      { status: 500 }
    );
  }
}

