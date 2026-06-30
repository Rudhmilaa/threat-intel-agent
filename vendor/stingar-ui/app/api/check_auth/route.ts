import { decrypt } from "@/app/auth/session";
import { cookies } from "next/headers";

export async function GET(request: Request) {
    // Development bypass: Always return 200 if bypass is enabled
    if (process.env.NODE_ENV === 'development' && process.env.NEXT_PUBLIC_BYPASS_AUTH === 'true') {
        return new Response(null, { status: 200 });
    }

    const cookie = (await cookies()).get('session')?.value;
    const session = await decrypt(cookie);
    if (!session?.userId) {
        return new Response(null, { status: 401 });
      }
    return new Response(null, { status: 200 });
}