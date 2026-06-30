import 'server-only';

import { readFileSync } from 'fs';
import type { SessionPayload } from '@/app/auth/definitions';
import { SignJWT, jwtVerify } from 'jose';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';

function getPassphrase(): string {
  const fromEnv = process.env.PASSPHRASE;
  if (fromEnv) return fromEnv;
  const envPath = process.env.STINGAR_ENV_PATH || '/app/stingar.env';
  try {
    const content = readFileSync(envPath, 'utf8');
    const m = content.match(/^PASSPHRASE=(.*)$/m);
    return m ? m[1].trim() : '';
  } catch {
    return '';
  }
}

export async function encrypt(payload: SessionPayload) {
  const secretKey = getPassphrase();
  if (!secretKey) {
    throw new Error('PASSPHRASE is not set. Run the configure script to generate stingar.env before starting.');
  }
  const key = new TextEncoder().encode(secretKey);
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('28 days')
    .sign(key);
}

export async function decrypt(session: string | undefined = '') {
  const secretKey = getPassphrase();
  if (!secretKey) return null;
  const key = new TextEncoder().encode(secretKey);
  try {
    const { payload } = await jwtVerify(session, key, {
      algorithms: ['HS256'],
    });
    return payload;
  } catch (error) {
    return null;
  }
}

export async function createSession(userId: string, doRedirect = false) {
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000 * 24 * 28); // 28 days
  const session = await encrypt({ userId, expiresAt });

  (await cookies()).set('session', session, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    expires: expiresAt,
    sameSite: 'lax',
    path: '/',
  });

  if (doRedirect) {
    redirect('/dashboard');
  }
}

export async function verifySession() {
  // Development bypass: Return mock session if bypass is enabled
  if (process.env.NODE_ENV === 'development' && process.env.NEXT_PUBLIC_BYPASS_AUTH === 'true') {
    return { isAuth: true, userId: 1 }; // Default to user ID 1 in dev mode
  }

  const cookie = (await cookies()).get('session')?.value;
  const session = await decrypt(cookie);

  if (!session?.userId) {
    redirect('/login');
  }

  return { isAuth: true, userId: Number(session.userId) };
}

export async function updateSession() {
  const session = (await cookies()).get('session')?.value;
  const payload = await decrypt(session);

  if (!session || !payload) {
    return null;
  }

  const expires = new Date(Date.now() + 60 * 60 * 1000 * 24 * 28); // 28 days
  (await cookies()).set('session', session, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    expires: expires,
    sameSite: 'lax',
    path: '/',
  });
}

export async function deleteSession() {
  (await cookies()).delete('session');
  redirect('/login');
}