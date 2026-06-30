import { NextRequest, NextResponse } from 'next/server';
import { createHoneypotRequest, getHoneypotRequests } from '@/lib/store-actions';
import { HoneypotRequestCreate } from '@/models/hp-request';

export async function POST(request: NextRequest) {
  try {
    const requestData: HoneypotRequestCreate = await request.json();

    // Validate required fields
    if (!requestData.title || !requestData.description) {
      return NextResponse.json(
        { error: 'Title and description are required' },
        { status: 400 }
      );
    }

    // Validate requester information
    if (!requestData.requesterName || requestData.requesterName.trim().length === 0) {
      return NextResponse.json(
        { error: 'Requester name is required' },
        { status: 400 }
      );
    }

    if (!requestData.requesterEmail || requestData.requesterEmail.trim().length === 0) {
      return NextResponse.json(
        { error: 'Requester email is required' },
        { status: 400 }
      );
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(requestData.requesterEmail)) {
      return NextResponse.json(
        { error: 'Invalid email format' },
        { status: 400 }
      );
    }

    if (!requestData.requesterOrganization || requestData.requesterOrganization.trim().length === 0) {
      return NextResponse.json(
        { error: 'Organization name or University name is required' },
        { status: 400 }
      );
    }

    const result = await createHoneypotRequest(requestData);
    return NextResponse.json(result);
  } catch (error: any) {
    console.error('Error creating honeypot request:', error);
    return NextResponse.json(
      { error: error.message || 'Failed to create request' },
      { status: 500 }
    );
  }
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') || '1');
    const perPage = parseInt(searchParams.get('perPage') || '50');
    const status = searchParams.get('status');
    const category = searchParams.get('category');
    const priority = searchParams.get('priority');

    const filters: any = {};
    if (status) filters.status = status;
    if (category) filters.category = category;
    if (priority) filters.priority = priority;

    const result = await getHoneypotRequests(page, perPage, filters);
    return NextResponse.json(result);
  } catch (error: any) {
    console.error('Error fetching requests:', error);
    return NextResponse.json(
      { error: 'Failed to fetch requests' },
      { status: 500 }
    );
  }
}

