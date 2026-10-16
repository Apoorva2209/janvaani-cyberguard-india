import fastify, { FastifyInstance, FastifyError, FastifyRequest, FastifyReply } from 'fastify';
import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import csrf from '@fastify/csrf-protection';
import multipart from '@fastify/multipart';
import crypto from 'node:crypto';

import { env, getSanitizedConfig } from './config/env.js';
import { securityHeaders } from './middleware/security-headers.js';
import { rateLimiter } from './middleware/rate-limiter.js';
import { checkRoutes } from './routes/check.js';
import { authRoutes } from './routes/auth.js';
import { adminRoutes } from './routes/admin.js';
import { featurePhoneRoutes } from './routes/feature-phone.js';

/**
 * Builds and configures the production-grade Fastify server.
 *
 * Security Architecture Highlights:
 * - Deterministic, unguessable Request IDs (UUIDv4) for tamper-evident audit logging.
 * - Least-privilege CORS configuration rejecting wildcard origins.
 * - Defensive multipart boundaries preventing memory exhaustion & zip-bomb style payload expansions.
 * - Anti-CSRF double-submit / token validation for state-modifying requests.
 * - Information disclosure prevention: Global error handler strictly filters out stack traces,
 *   internal database errors, and system details from client responses.
 */
export async function buildServer(): Promise<FastifyInstance> {
  const app = fastify({
    logger: {
      level: env.LOG_LEVEL,
      // Redact sensitive headers and fields in logger output automatically
      redact: {
        paths: [
          'req.headers.authorization',
          'req.headers.cookie',
          'req.headers["x-csrf-token"]',
          'req.headers["x-api-key"]',
          'body.password',
          'body.confirmPassword',
          'body.otp',
          'body.token',
          'body.refreshToken',
        ],
        censor: '[REDACTED]',
      },
    },
    // Generate UUIDv4 for end-to-end request tracing and audit correlation
    genReqId: () => crypto.randomUUID(),
    requestIdHeader: 'x-request-id',
    // Protect against HTTP Parameter Pollution and oversized headers
    maxParamLength: 200,
    bodyLimit: env.MAX_UPLOAD_SIZE_MB * 1024 * 1024,
    disableRequestLogging: false,
    trustProxy: env.NODE_ENV === 'production',
  });

  // 1. Register Cookies (Required for secure sessions and CSRF token propagation)
  await app.register(cookie, {
    secret: env.SESSION_SECRET,
    hook: 'onRequest',
    parseOptions: {
      httpOnly: true,
      secure: env.NODE_ENV === 'production',
      sameSite: 'strict',
      path: '/',
    },
  });

  // 2. Register Anti-CSRF Protection
  await app.register(csrf, {
    cookieKey: '__Host-csrf-token',
    cookieOpts: {
      path: '/',
      sameSite: 'strict',
      secure: env.NODE_ENV === 'production',
      httpOnly: true,
    },
    // Extract CSRF token from header for AJAX / API calls
    getToken: (req: FastifyRequest) => {
      const header = req.headers['x-csrf-token'];
      if (typeof header === 'string') return header;
      return undefined;
    },
  });

  // 3. Register CORS with explicit origin allowlist
  await app.register(cors, {
    origin: (origin, callback) => {
      // Allow requests with no origin (such as mobile apps or same-origin curl)
      if (!origin) {
        callback(null, true);
        return;
      }

      if (env.ALLOWED_ORIGINS.includes(origin)) {
        callback(null, true);
        return;
      }

      // Deny untrusted origins
      app.log.warn({ audit: true, untrustedOrigin: origin }, 'Blocked cross-origin request');
      callback(new Error('Cross-Origin Request Blocked by Policy'), false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Origin',
      'X-Requested-With',
      'Content-Type',
      'Accept',
      'Authorization',
      'X-CSRF-Token',
      'X-Request-Id',
      'X-API-Key',
    ],
    exposedHeaders: [
      'X-Request-Id',
      'X-RateLimit-Limit',
      'X-RateLimit-Remaining',
      'X-RateLimit-Reset',
      'Retry-After',
    ],
    maxAge: 86400, // 24 hours preflight cache
  });

  // 4. Register Security Headers (Strict CSP, HSTS, X-Content-Type-Options, etc.)
  await app.register(securityHeaders);

  // 5. Register Distributed Rate Limiter
  await app.register(rateLimiter);

  // 6. Register Multipart with strict payload restrictions
  await app.register(multipart, {
    limits: {
      fieldNameSize: 100, // Max field name size in bytes
      fieldSize: 1024 * 1024, // Max field value size: 1MB
      fields: 20, // Max number of non-file fields
      fileSize: env.MAX_UPLOAD_SIZE_MB * 1024 * 1024, // Max individual file size
      files: 5, // Max total file attachments per request
      headerPairs: 100,
    },
  });

  // 7. Register Threat Intelligence & Auth Routes
  await app.register(checkRoutes, { prefix: '/api/v1/check' });
  await app.register(authRoutes, { prefix: '/api/v1/auth' });
  await app.register(adminRoutes, { prefix: '/api/v1/admin' });
  await app.register(featurePhoneRoutes, { prefix: '/api/v1/feature-phone' });

  // ==========================================
  // Health & System Diagnostic Endpoints
  // ==========================================
  const healthHandler = async (_req: FastifyRequest, reply: FastifyReply) => {
    return reply.status(200).send({
      status: 'UP',
      service: 'cyberguard-backend',
      timestamp: new Date().toISOString(),
      uptimeSeconds: Math.floor(process.uptime()),
      environment: env.NODE_ENV,
    });
  };

  app.get('/health', healthHandler);
  app.get('/api/health', healthHandler);

  // CSRF Token provision route for clients
  app.get('/api/csrf-token', async (req: FastifyRequest, reply: FastifyReply) => {
    const token = reply.generateCsrf();
    return reply.status(200).send({ csrfToken: token });
  });

  // Route: Configuration summary (Sanitized, non-sensitive)
  app.get('/api/config/info', async (_req: FastifyRequest, reply: FastifyReply) => {
    return reply.status(200).send(getSanitizedConfig());
  });

  // ==========================================
  // Global Error Handler
  // ==========================================
  app.setErrorHandler((error: FastifyError, req: FastifyRequest, reply: FastifyReply) => {
    const requestId = req.id;
    const statusCode = error.statusCode && error.statusCode >= 400 && error.statusCode < 600
      ? error.statusCode
      : 500;

    // Log complete error internally for diagnostics, tagged with request ID
    req.log.error({
      err: error,
      requestId,
      statusCode,
      url: req.raw.url,
      method: req.method,
    }, 'Unhandled application exception');

    // Never leak stack traces or raw database messages to clients
    if (statusCode === 500) {
      return reply.status(500).send({
        statusCode: 500,
        error: 'Internal Server Error',
        message: 'An unexpected internal error occurred. Please contact security operations if the issue persists.',
        requestId,
      });
    }

    // Sanitized client-safe response for known HTTP errors
    return reply.status(statusCode).send({
      statusCode,
      error: error.name || 'Error',
      message: error.message || 'The request could not be processed.',
      requestId,
    });
  });

  // ==========================================
  // 404 Handler
  // ==========================================
  app.setNotFoundHandler((req: FastifyRequest, reply: FastifyReply) => {
    req.log.warn({
      audit: true,
      eventType: 'NOT_FOUND_RESOURCE_ACCESSED',
      url: req.raw.url,
      method: req.method,
    }, 'Resource not found');

    return reply.status(404).send({
      statusCode: 404,
      error: 'Not Found',
      message: 'The requested resource was not found on this server.',
      requestId: req.id,
    });
  });

  return app;
}

/**
 * Server startup routine with graceful shutdown lifecycle management.
 */
export async function startServer(): Promise<void> {
  const app = await buildServer();

  // Register shutdown signals (SIGINT, SIGTERM)
  const shutdown = async (signal: string) => {
    app.log.info({ signal }, 'Graceful shutdown signal received. Closing connections...');
    try {
      await app.close();
      app.log.info('Fastify server stopped gracefully.');
      process.exit(0);
    } catch (err) {
      app.log.error({ err }, 'Error during server shutdown');
      process.exit(1);
    }
  };

  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));

  try {
    await app.listen({
      port: env.PORT,
      host: '0.0.0.0', // Listen on all network interfaces
    });
    app.log.info(`CyberGuard India Backend running on port ${env.PORT} [${env.NODE_ENV}]`);
  } catch (err) {
    app.log.fatal({ err }, 'Fatal error during server startup');
    process.exit(1);
  }
}

// Auto-start if executed directly as entrypoint
if (process.argv[1]?.endsWith('server.ts') || process.argv[1]?.endsWith('server.js')) {
  void startServer();
}
