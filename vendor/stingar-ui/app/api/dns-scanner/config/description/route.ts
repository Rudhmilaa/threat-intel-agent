import { NextRequest, NextResponse } from "next/server";
import { getStoreData, postStoreData } from "@/lib/store-actions";

export async function GET(request: NextRequest) {
  try {
    const response = await getStoreData("/dns-scanner/config/description");
    
    return NextResponse.json(response);
  } catch (error: any) {
    return NextResponse.json(
      { detail: error.message || "Failed to fetch description" },
      { status: 500 }
    );
  }
}

export async function PATCH(request: NextRequest) {
  try {
    const body = await request.json();
    
    const response = await postStoreData(
      "/dns-scanner/config/description",
      body,
      "PATCH"
    );
    
    return NextResponse.json(response);
  } catch (error: any) {
    return NextResponse.json(
      { detail: error.message || "Failed to update description" },
      { status: 500 }
    );
  }
}

