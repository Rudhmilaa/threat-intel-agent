import { NextRequest, NextResponse } from "next/server";
import { postStoreData } from "@/lib/store-actions";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    
    const response = await postStoreData(
      "/dns-scanner/scan",
      body,
      "POST"
    );
    
    return NextResponse.json(response);
  } catch (error: any) {
    return NextResponse.json(
      { detail: error.message || "Failed to start scan" },
      { status: 500 }
    );
  }
}

