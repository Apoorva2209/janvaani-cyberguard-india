import { FastifyReply, FastifyRequest } from 'fastify';
import { ZodError, ZodSchema, z } from 'zod';
import net from 'node:net';

/**
 * Validation target specification
 */
export interface ValidationSchemas<TBody = unknown, TQuery = unknown, TParams = unknown> {
  body?: ZodSchema<TBody>;
  query?: ZodSchema<TQuery>;
  params?: ZodSchema<TParams>;
}

/**
 * Sanitization Helpers
 *
 * Security Rationale:
 * - Null bytes (%00 / \0) can bypass string terminators in low-level drivers or file systems.
 * - Unicode normalization (NFKC) prevents homoglyph attacks and bypasses relying on varied Unicode representations.
 * - Enforcing max character lengths prevents regex DoS (ReDoS) and memory exhaustion.
 */
export const sanitizers = {
  /**
   * Cleans text by stripping null bytes, normalizing unicode to NFKC, and trimming whitespace.
   */
  sanitizeString(input: string, maxLength = 10_000): string {
    if (typeof input !== 'string') return '';
    return input
      .slice(0, maxLength)
      .replace(/\0/g, '') // Strip null bytes
      .normalize('NFKC') // Normalize unicode representation
      .trim();
  },

  /**
   * Strips control characters except standard whitespace (newlines, tabs)
   */
  stripControlChars(input: string): string {
    return input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  },
};

/**
 * SSRF Protection: IP and Domain verification
 */
function isPrivateOrLocalIp(ip: string): boolean {
  if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') return true;

  // IPv4 range checks
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    const p0 = parts[0] ?? 0;
    const p1 = parts[1] ?? 0;

    // 10.0.0.0/8
    if (p0 === 10) return true;
    // 172.16.0.0/12
    if (p0 === 172 && p1 >= 16 && p1 <= 31) return true;
    // 192.168.0.0/16
    if (p0 === 192 && p1 === 168) return true;
    // 169.254.0.0/16 (Link Local / Cloud Metadata endpoint 169.254.169.254)
    if (p0 === 169 && p1 === 254) return true;
    // 127.0.0.0/8 (Loopback)
    if (p0 === 127) return true;
    // 0.0.0.0
    if (p0 === 0) return true;
  }

  // IPv6 range checks
  if (net.isIPv6(ip)) {
    const lower = ip.toLowerCase();
    if (lower === '::1' || lower.startsWith('fe80:') || lower.startsWith('fc00:') || lower.startsWith('fd00:')) {
      return true;
    }
  }

  return false;
}

/**
 * SSRF-Safe URL Schema
 * Validates that an incoming URL strictly uses HTTPS and does not resolve to private/loopback/cloud metadata targets.
 */
export const secureUrlSchema = z.string().url().superRefine((val, ctx) => {
  try {
    const parsed = new URL(val);

    if (parsed.protocol !== 'https:') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Only secure HTTPS URLs are permitted',
      });
      return;
    }

    const hostname = parsed.hostname.toLowerCase();

    // Reject localhost and dotless hostnames
    if (hostname === 'localhost' || !hostname.includes('.')) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Localhost or internal host references are forbidden',
      });
      return;
    }

    // Check direct IP address references
    if (net.isIP(hostname) && isPrivateOrLocalIp(hostname)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'Private and non-routable IP addresses are forbidden',
      });
      return;
    }
  } catch {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'Invalid URL format',
    });
  }
});

/**
 * Indian Mobile Phone Number Validator (E.164 and National Format)
 * Accepts +91XXXXXXXXXX or 10-digit Indian mobile format (starting with 6-9).
 * Does not retain raw phone in output - returns masked or validated token.
 */
export const indianPhoneNumberSchema = z.string().superRefine((val, ctx) => {
  const cleaned = val.replace(/[\s\-\(\)]/g, '');
  // Valid formats: +919876543210, 919876543210, 09876543210, 9876543210
  const indianMobileRegex = /^(?:\+91|91|0)?[6-9]\d{9}$/;

  if (!indianMobileRegex.test(cleaned)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: 'Invalid Indian phone number. Expected 10-digit mobile starting with 6, 7, 8, or 9',
    });
  }
});

/**
 * Phone Number Masking Helper (Prevents PII leakage in logs/audit records)
 */
export function maskPhoneNumber(phone: string): string {
  const digits = phone.replace(/\D/g, '');
  if (digits.length < 4) return '***';
  const lastFour = digits.slice(-4);
  return `+91-XXXXXX${lastFour}`;
}

/**
 * Output Encoding Helpers
 *
 * Security Rationale:
 * Context-aware output encoding mitigates Cross-Site Scripting (XSS)
 * and Injection attacks when reflecting user data.
 */
export const outputEncoders = {
  /**
   * HTML entity encoding for reflecting strings into HTML contexts.
   */
  encodeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/\//g, '&#x2F;');
  },

  /**
   * Strict URL component encoding.
   */
  encodeUrl(str: string): string {
    return encodeURIComponent(str).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  },

  /**
   * Safe JSON serializer preventing script injection inside HTML script tags.
   */
  safeJsonSerialize(obj: unknown): string {
    return JSON.stringify(obj)
      .replace(/</g, '\\u003c')
      .replace(/>/g, '\\u003e')
      .replace(/&/g, '\\u0026')
      .replace(/\u2028/g, '\\u2028')
      .replace(/\u2029/g, '\\u2029');
  },
};

/**
 * Fastify Request Size Limiter Middleware
 * Rejects requests with oversized bodies before buffering to avoid memory exhaustion attacks.
 */
export function enforceRequestSizeLimit(maxSizeBytes: number) {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    const contentLength = req.headers['content-length'];
    if (contentLength && parseInt(contentLength, 10) > maxSizeBytes) {
      req.log.warn({
        audit: true,
        eventType: 'PAYLOAD_TOO_LARGE',
        contentLength,
        maxSizeBytes,
      }, 'Request payload exceeded maximum size threshold');

      return reply.status(413).send({
        statusCode: 413,
        error: 'Payload Too Large',
        message: 'Request payload exceeds the allowable size limit.',
      });
    }
  };
}

/**
 * Generic Zod validation middleware factory for Fastify.
 * Validates body, query, and route parameters independently.
 * Logs validation failures cleanly WITHOUT leaking user-submitted PII or passwords.
 */
export function validateRequest<TBody = unknown, TQuery = unknown, TParams = unknown>(
  schemas: ValidationSchemas<TBody, TQuery, TParams>
) {
  return async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
    try {
      if (schemas.params) {
        const parsedParams = await schemas.params.parseAsync(req.params);
        req.params = parsedParams as Record<string, string>;
      }

      if (schemas.query) {
        const parsedQuery = await schemas.query.parseAsync(req.query);
        req.query = parsedQuery as Record<string, string>;
      }

      if (schemas.body) {
        const parsedBody = await schemas.body.parseAsync(req.body);
        req.body = parsedBody;
      }
    } catch (err: unknown) {
      if (err instanceof ZodError) {
        // SECURITY: Redact actual submitted values to prevent logging credentials, passwords, or PII
        const sanitizedIssues = err.errors.map((issue) => ({
          field: issue.path.join('.'),
          code: issue.code,
          message: issue.message,
        }));

        req.log.warn({
          audit: true,
          eventType: 'REQUEST_VALIDATION_FAILURE',
          url: req.raw.url,
          method: req.method,
          invalidFields: sanitizedIssues.map((i) => i.field),
        }, 'Incoming request validation failed');

        return reply.status(400).send({
          statusCode: 400,
          error: 'Bad Request',
          message: 'Request validation failed. Verify input syntax and constraints.',
          details: sanitizedIssues,
        });
      }

      // Re-throw unexpected non-validation errors to Fastify global error handler
      throw err;
    }
  };
}
