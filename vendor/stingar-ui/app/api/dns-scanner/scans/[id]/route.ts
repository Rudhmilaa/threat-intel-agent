import { NextRequest, NextResponse } from "next/server";
import { getStoreData } from "@/lib/store-actions";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const response = await getStoreData(`/dns-scanner/scans/${id}`);

    return NextResponse.json(response);
  } catch (error: any) {
    return NextResponse.json(
      { detail: error.message || "Failed to fetch scan" },
      { status: 500 }
    );
  }
}

