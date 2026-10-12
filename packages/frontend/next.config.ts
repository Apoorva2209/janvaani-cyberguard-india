import type { NextConfig } from 'next';

/**
 * Security-hardened Next.js configuration for CyberGuard India.
 *
 * Security rationale:
 * 1. Content Security Policy (CSP): Prevents XSS, unauthorized script execution, clickjacking, and data exfiltration.
 * 2. Strict Transport Security (HSTS): Enforces HTTPS with preload and subdomains to prevent SSL stripping (MITM).
 * 3. X-Frame-Options: Set to 'DENY' to prohibit embedding in frames/iframes (mitigates UI redressing/clickjacking).
 * 4. X-Content-Type-Options: 'nosniff' prevents MIME-sniffing exploits.
 * 5. Referrer-Policy: 'strict-origin-when-cross-origin' limits leakage of path and query params containing sensitive IDs.
 * 6. Permissions-Policy: Disables invasive browser APIs (geolocation, camera, microphone, payment) not required by the app.
 * 7. Powered-by removal: Removes 'X-Powered-By: Next.js' header to avoid unnecessary framework fingerprinting.
 * 8. Image Optimization Whitelist: No remote image patterns allowed by default to prevent SSRF and arbitrary media loading.
 * 9. Output Standalone: Produces a minimal Docker image containing only required production dependencies.
 */

const isProd = process.env.NODE_ENV === 'production';

// Strict Content Security Policy directives
// Note: Middleware generates a dynamic nonce per request. For static assets or base config,
// we define strict baseline policies.
const contentSecurityPolicy = `
  default-src 'self';
  script-src 'self' 'unsafe-eval';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: blob:;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  connect-src 'self' ${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000'};
  block-all-mixed-content;
  upgrade-insecure-requests;
`.replace(/\s{2,}/g, ' ').trim();

const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: contentSecurityPolicy,
  },
  {
    key: 'X-DNS-Prefetch-Control',
    value: 'on',
  },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload',
  },
  {
    key: 'X-Frame-Options',
    value: 'DENY',
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff',
  },
  {
    key: 'X-XSS-Protection',
    value: '1; mode=block',
  },
  {
    key: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin',
  },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), browsing-topics=(), payment=()',
  },
  {
    key: 'Cross-Origin-Opener-Policy',
    value: 'same-origin',
  },
  {
    key: 'Cross-Origin-Resource-Policy',
    value: 'same-origin',
  },
];

const nextConfig: NextConfig = {
  // Minimize container footprint and attack surface in production Docker environments
  output: 'standalone',

  // Disable server-identifying header
  poweredByHeader: false,

  // Strict React mode enables additional lifecycle checks to catch memory leaks & concurrency bugs
  reactStrictMode: true,

  // Disallow arbitrary remote images to prevent SSRF and untrusted media rendering
  images: {
    remotePatterns: [],
    dangerouslyAllowSVG: false,
    contentDispositionType: 'attachment',
    contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;",
  },

  // Apply strict HTTP security headers to all routes
  async headers() {
    return [
      {
        source: '/:path*',
        headers: securityHeaders,
      },
    ];
  },
};

export default nextConfig;
