import { NextRequest, NextResponse } from "next/server";
import { postStoreData } from "@/lib/store-actions";

export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;
    const body = await request.json();
    
    const response = await postStoreData(
      `/dns-scanner/results/${id}`,
      body,
      "PATCH"
    );
    
    return NextResponse.json(response);
  } catch (error: any) {
    return NextResponse.json(
      { detail: error.message || "Failed to update result" },
      { status: 500 }
    );
  }
}

