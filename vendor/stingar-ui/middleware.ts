import { NextRequest, NextResponse } from 'next/server';
import { decrypt } from '@/app/auth/session';
import { cookies } from 'next/headers';

// Public page routes (no session required).
const publicRoutes = ['/login', '/', '/initial-admin'];

// API route handlers that must stay reachable without a session.
// `/api/check_auth` is the session probe itself (also the target of the
// `/check_auth` rewrite and nginx's `auth_request`), so it cannot require
// a valid session to run.
const publicApiRoutes = ['/api/check_auth'];

// Development bypass: Set NEXT_PUBLIC_BYPASS_AUTH=true to skip authentication in dev
const BYPASS_AUTH = process.env.NODE_ENV === 'development' && process.env.NEXT_PUBLIC_BYPASS_AUTH === 'true';

function isPublicApiRoute(path: string): boolean {
  return publicApiRoutes.some((route) => path === route || path.startsWith(`${route}/`));
}

export default async function middleware(req: NextRequest) {
  const path = req.nextUrl.pathname;
  const isApi = path.startsWith('/api');

  // In development with bypass enabled, skip all auth checks
  if (BYPASS_AUTH) {
    // Still redirect from login page to dashboard when bypass is active
    if (!isApi && (path === '/login' || path === '/')) {
      return NextResponse.redirect(new URL('/dashboard', req.nextUrl));
    }
    return NextResponse.next();
  }

  // Decrypt the session from the cookie
  const cookie = (await cookies()).get('session')?.value;
  const session = await decrypt(cookie);

  // Gate the UI's own /api/* route handlers. These run inside the stingar-ui
  // container and proxy to apiarist with the master API key, so they must
  // require an authenticated session. Reachable publicly via nginx `location /`,
  // so without this check they are unauthenticated proxies to the API.
  if (isApi) {
    if (isPublicApiRoute(path)) {
      return NextResponse.next();
    }
    if (!session?.userId) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    return NextResponse.next();
  }

  // Check if the current route is public
  const isPublicRoute = publicRoutes.includes(path);

  // Redirect unauthenticated users to initial-admin (first-time setup) instead of login.
  // The initial-admin page will redirect to /login if admin already has a password.
  if (!isPublicRoute && !session?.userId) {
    return NextResponse.redirect(new URL('/initial-admin', req.nextUrl));
  }

  // Redirect authenticated users trying to access public routes (e.g., login or signup) to the dashboard
  if (
    isPublicRoute &&
    session?.userId &&
    !req.nextUrl.pathname.startsWith('/dashboard')
  ) {
    return NextResponse.redirect(new URL('/dashboard', req.nextUrl));
  }

  return NextResponse.next();
}

// Run middleware on all routes except static assets. Unlike before, this now
// INCLUDES /api/* so the route-handler gate above is enforced.
export const config = {
  matcher: ['/((?!_next/static|_next/image|.*\\.png$).*)'],
}
