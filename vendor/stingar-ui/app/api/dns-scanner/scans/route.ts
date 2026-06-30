import { NextRequest, NextResponse } from "next/server";
import { getStoreData } from "@/lib/store-actions";

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const params = new URLSearchParams();
    
    searchParams.forEach((value, key) => {
      params.append(key, value);
    });
    
    const queryString = params.toString();
    const endpoint = `/dns-scanner/scans${queryString ? `?${queryString}` : ""}`;
    
    const response = await getStoreData(endpoint);
    
    return NextResponse.json(response);
  } catch (error: any) {
    return NextResponse.json(
      { detail: error.message || "Failed to fetch scans" },
      { status: 500 }
    );
  }
}

