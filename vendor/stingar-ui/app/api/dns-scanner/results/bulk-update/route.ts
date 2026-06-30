import { NextRequest, NextResponse } from "next/server";
import { postStoreData } from "@/lib/store-actions";

export async function PATCH(request: NextRequest) {
  try {
    const body = await request.json();
    
    const response = await postStoreData(
      "/dns-scanner/results/bulk-update",
      body,
      "PATCH"
    );
    
    return NextResponse.json(response);
  } catch (error: any) {
    return NextResponse.json(
      { detail: error.message || "Failed to bulk update" },
      { status: 500 }
    );
  }
}

