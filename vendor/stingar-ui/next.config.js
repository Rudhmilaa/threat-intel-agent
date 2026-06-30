/** @type {import('next').NextConfig} */
const nextConfig = {
  // Enable standalone output for smaller Docker images
  output: 'standalone',
  env: {
    NEXT_PUBLIC_VERSION: process.env.npm_package_version,
    // Baked at `next build` from Dockerfile ARG THREAT_FEEDS_ENABLED; also read at
    // request time in app/(dashboard)/layout.tsx (force-dynamic).
    THREAT_FEEDS_ENABLED: process.env.THREAT_FEEDS_ENABLED,
  },
  // Disable static page generation cache to prevent Server Action hash mismatches
  experimental: {
    serverActions: {
      bodySizeLimit: '2mb',
      // Allow Server Actions when behind nginx proxy (IAP tunnel uses localhost:8443)
      allowedOrigins: ['localhost:8443', 'localhost:443', 'localhost'],
    },
  },
  // Remove console logs in production builds
  compiler: {
    removeConsole: process.env.NODE_ENV === 'production' ? {
      exclude: ['error', 'warn'], // Keep error and warn logs for production debugging
    } : false,
  },
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-XSS-Protection',
            value: '1; mode=block',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
        ],
      },
      {
        // Prevent caching of HTML pages in development to avoid Server Action hash mismatches
        source: '/dashboard',
        headers: [
          {
            key: 'Cache-Control',
            value: 'no-store, no-cache, must-revalidate, proxy-revalidate',
          },
        ],
      },
      {
        // Prevent caching of JavaScript bundles to avoid Server Action hash mismatches
        source: '/_next/static/:path*',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=31536000, immutable',
          },
        ],
      },
      {
        // Prevent caching of Server Action endpoints
        source: '/_next/server-actions/:path*',
        headers: [
          {
            key: 'Cache-Control',
            value: 'no-store, must-revalidate',
          },
        ],
      },
    ];
  },
  async redirects() {
    return [
      {
        source: '/', // The route to redirect from
        destination: '/dashboard', // The target route
        permanent: true, // Indicates if the redirect is permanent (301) or temporary (307)
      }
    ];
  },
  async rewrites() {
    return [
      {
        source: '/check_auth',
        destination: '/api/check_auth',
      }
    ];
  },
}

module.exports = nextConfig
