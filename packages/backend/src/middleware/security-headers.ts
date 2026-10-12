import { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import crypto from 'node:crypto';

declare module 'fastify' {
  interface FastifyReply {
    cspNonce?: string;
  }
}

/**
 * Security Headers Plugin for Fastify.
 *
 * Security Rationale:
 * - CSP: Mitigates XSS and data injection attacks by enforcing strict resource origins and requiring cryptographic nonces for script execution.
 * - Nonce Generation: Uses cryptographically secure random bytes (CSPRNG) per request.
 * - X-Content-Type-Options: Prevents MIME-sniffing which could execute attacker-controlled payloads as scripts.
 * - X-Frame-Options: Prevents clickjacking attacks by forbidding embedding within iframes/frames.
 * - X-XSS-Protection: Disabled ('0') per OWASP recommendations because legacy auditors in old browsers introduced new vulnerability vectors.
 * - Referrer-Policy: Prevents sensitive token or URL path leakage in referrer headers to external third parties.
 * - Permissions-Policy: Disables powerful browser APIs (camera, microphone, geolocation, payment) that are not needed by the backend API.
 * - HSTS: Forces modern browsers to communicate exclusively over TLS, preventing SSL-stripping and man-in-the-middle attacks.
 * - COOP & CORP: Prevents cross-origin side-channel attacks (like Spectre) and unauthorized cross-origin reads.
 * - Cache-Control: Mandates no-store on sensitive API endpoints to protect personally identifiable information (PII) from browser/proxy caching.
 */
const securityHeadersPlugin: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  // Generate request-specific CSP nonce on incoming requests
  fastify.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    // Generate a 128-bit cryptographically secure base64 nonce
    const nonce = crypto.randomBytes(16).toString('base64');
    reply.cspNonce = nonce;
  });

  // Apply strict HTTP response security headers
  fastify.addHook('onSend', async (request: FastifyRequest, reply: FastifyReply, payload) => {
    const nonce = reply.cspNonce ?? crypto.randomBytes(16).toString('base64');

    // Content-Security-Policy (CSP)
    const cspDirectives = [
      "default-src 'none'",
      `script-src 'strict-dynamic' 'nonce-${nonce}' 'unsafe-inline' https:`,
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self' data:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'",
      "upgrade-insecure-requests",
    ].join('; ');

    reply.header('Content-Security-Policy', cspDirectives);
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('X-Frame-Options', 'DENY');
    reply.header('X-XSS-Protection', '0');
    reply.header('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Permissions-Policy (Feature Policy) - disable unnecessary hardware/device APIs
    reply.header(
      'Permissions-Policy',
      'camera=(), microphone=(), geolocation=(), payment=(), usb=(), screen-wake-lock=()'
    );

    // HTTP Strict Transport Security (HSTS) - 1 year max-age with subdomains and preload eligibility
    reply.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');

    // Cross-Origin Isolation
    reply.header('Cross-Origin-Opener-Policy', 'same-origin');
    reply.header('Cross-Origin-Resource-Policy', 'same-origin');

    // Prevent caching for API JSON responses to avoid PII / credential persistence in caches
    const contentType = reply.getHeader('content-type');
    if (!contentType || String(contentType).includes('application/json')) {
      reply.header('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      reply.header('Pragma', 'no-cache');
      reply.header('Expires', '0');
      reply.header('Surrogate-Control', 'no-store');
    }

    return payload;
  });
};

export const securityHeaders = fp(securityHeadersPlugin, {
  name: 'cyberguard-security-headers',
});
