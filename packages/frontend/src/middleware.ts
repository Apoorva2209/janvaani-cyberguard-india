import { NextResponse, type NextRequest } from 'next/server';

/**
 * Next.js Edge Middleware for CyberGuard India.
 *
 * Security rationale:
 * 1. Cryptographic Nonce Generation: Uses Web Crypto API (crypto.randomUUID()) to create
 *    a unique, non-guessable nonce per request for strict CSP script-src enforcement without 'unsafe-inline'.
 * 2. HTTPS Redirection: Enforces TLS in production to prevent man-in-the-middle downgrade attacks.
 * 3. CSRF Defense: Inspects state-changing HTTP mutation requests (POST, PUT, PATCH, DELETE) for custom
 *    CSRF headers or origin verification, preventing Cross-Site Request Forgery attacks.
 * 4. Rate-Limit Awareness: Checks for rate-limit violations (e.g. from upstream edge proxy/gateway)
 *    and delivers sanitized 429 responses with clear retry guidance.
 * 5. Comprehensive Security Headers: Injects defence-in-depth headers on every outgoing response.
 */

const MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export function middleware(request: NextRequest): NextResponse {
  const { pathname } = request.nextUrl;

  // 1. Production HTTPS Redirection
  const proto = request.headers.get('x-forwarded-proto');
  const host = request.headers.get('host');
  if (process.env.NODE_ENV === 'production' && proto === 'http' && host) {
    const httpsUrl = `https://${host}${request.nextUrl.pathname}${request.nextUrl.search}`;
    return NextResponse.redirect(httpsUrl, 301);
  }

  // 2. Cryptographic Nonce Generation
  // Buffer / crypto.randomUUID() generates a secure 128-bit pseudorandom nonce
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');

  // 3. Formulate per-request dynamic CSP containing the nonce
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';
  const cspHeaderValue = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    "style-src 'self' 'unsafe-inline'", // Tailwind CSS generates atomic utilities requiring style-src
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    `connect-src 'self' ${apiUrl}`,
    'block-all-mixed-content',
    'upgrade-insecure-requests',
  ]
    .join('; ')
    .trim();

  // 4. CSRF Validation for mutation requests on API proxy/internal routes
  // Safe methods (GET, HEAD, OPTIONS) do not alter state
  if (MUTATION_METHODS.has(request.method)) {
    const origin = request.headers.get('origin');
    const hostHeader = request.headers.get('host');

    // If Origin is present, ensure it matches the current Host to protect against cross-origin forgery
    if (origin && hostHeader) {
      try {
        const originUrl = new URL(origin);
        if (originUrl.host !== hostHeader) {
          return new NextResponse(
            JSON.stringify({
              error: 'Forbidden',
              message: 'Cross-origin request blocked due to origin mismatch.',
            }),
            {
              status: 403,
              headers: {
                'Content-Type': 'application/json',
              },
            }
          );
        }
      } catch {
        return new NextResponse(
          JSON.stringify({
            error: 'Bad Request',
            message: 'Malformed origin header provided.',
          }),
          { status: 400, headers: { 'Content-Type': 'application/json' } }
        );
      }
    }
  }

  // 5. Upstream Rate-Limit Awareness
  // If request contains rate-limit exhaustion marker from edge WAF or reverse proxy
  const rateLimitRemaining = request.headers.get('x-ratelimit-remaining');
  if (rateLimitRemaining === '0') {
    const retryAfter = request.headers.get('retry-after') || '60';
    return new NextResponse(
      JSON.stringify({
        error: 'Too Many Requests',
        message: 'Request limit exceeded. Please wait a moment before trying again.',
        retryAfterSeconds: parseInt(retryAfter, 10),
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': retryAfter,
        },
      }
    );
  }

  // Clone request headers to inject the CSP nonce for Next.js Server Components
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('Content-Security-Policy', cspHeaderValue);

  // Initialize response passing the updated request headers
  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });

  // 6. Set defense-in-depth security response headers
  response.headers.set('Content-Security-Policy', cspHeaderValue);
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-XSS-Protection', '1; mode=block');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), browsing-topics=(), payment=()'
  );

  return response;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except for:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public asset folders
     */
    {
      source: '/((?!_next/static|_next/image|favicon.ico|assets).*)',
      missing: [
        { type: 'header', key: 'next-router-prefetch' },
        { type: 'header', key: 'purpose', value: 'prefetch' },
      ],
    },
  ],
};
