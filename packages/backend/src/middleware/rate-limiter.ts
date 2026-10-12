import { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import { Redis } from 'ioredis';
import { env } from '../config/env.js';

export interface RateLimitOptions {
  windowMs: number;
  max: number;
  keyGenerator: (req: FastifyRequest) => string;
  name: string;
}

export interface RateLimitTierConfig {
  global: { windowMs: number; max: number };
  auth: { windowMs: number; max: number };
  upload: { windowMs: number; max: number };
  report: { windowMs: number; max: number };
}

export const RATE_LIMIT_TIERS: RateLimitTierConfig = {
  // Global tier: 100 req/min per IP
  global: { windowMs: 60_000, max: 100 },
  // Auth tier: 5 req/min per IP (Brute force & credential stuffing defense)
  auth: { windowMs: 60_000, max: 5 },
  // Upload tier: 10 req/min per user / IP (DDoS and storage exhaustion defense)
  upload: { windowMs: 60_000, max: 10 },
  // Report tier: 20 req/min per user / IP (Spam submission defense)
  report: { windowMs: 60_000, max: 20 },
};

/**
 * Extract normalized client IP address from request.
 * Takes into account reverse proxies when properly configured, otherwise raw socket IP.
 */
export function getClientIp(req: FastifyRequest): string {
  // Fastify handles trustProxy if configured; fallback safely to socket remote address
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') {
    const firstIp = forwarded.split(',')[0]?.trim();
    if (firstIp) return firstIp;
  }
  return req.ip || req.socket.remoteAddress || '127.0.0.1';
}

/**
 * Key Generators for varied rate limiting contexts
 */
export const keyGenerators = {
  byIp: (req: FastifyRequest): string => {
    return `ip:${getClientIp(req)}`;
  },
  byUserIdOrIp: (req: FastifyRequest): string => {
    // If authenticated user is attached to request (e.g., req.user.id), prioritize user ID
    const user = (req as unknown as { user?: { id?: string } }).user;
    if (user?.id) {
      return `user:${user.id}`;
    }
    return `ip:${getClientIp(req)}`;
  },
  byApiKeyOrIp: (req: FastifyRequest): string => {
    const apiKey = req.headers['x-api-key'];
    if (typeof apiKey === 'string' && apiKey.length > 0) {
      return `key:${apiKey}`;
    }
    return `ip:${getClientIp(req)}`;
  },
};

/**
 * Sliding Window Redis-backed Rate Limiter.
 *
 * Security Rationale:
 * - Sliding window algorithm prevents burst traffic exploits at boundary resets (common flaw in fixed-window limiters).
 * - Multi-tiered limits protect sensitive endpoints (login, OTP, reports, uploads) with targeted policies.
 * - Abuse threshold tracking: IPs exceeding 5x the configured limit are flagged for potential DDoS / malicious automation.
 * - Retry-After and standard rate-limit headers provide compliance with RFC 6585.
 * - In-memory fallback allows system resiliency in temporary Redis outages without crashing Fastify.
 */
export class SlidingWindowRateLimiter {
  private redis: Redis | null = null;
  // Local in-memory sliding window fallback map: key -> timestamps array
  private memoryFallback = new Map<string, number[]>();

  constructor(redisUrl?: string) {
    if (redisUrl) {
      try {
        this.redis = new Redis(redisUrl, {
          lazyConnect: true,
          enableOfflineQueue: false,
          maxRetriesPerRequest: 1,
        });

        this.redis.on('error', (err: Error) => {
          // Log error without sensitive credentials; fallback gracefully
          console.error('[RateLimiter] Redis connection error, falling back to in-memory store:', err.message);
        });
      } catch (err) {
        console.error('[RateLimiter] Failed to initialize Redis client, using in-memory store');
      }
    }
  }

  public async connect(): Promise<void> {
    if (this.redis) {
      try {
        await this.redis.connect();
      } catch {
        // Will fallback to memory
      }
    }
  }

  public async close(): Promise<void> {
    if (this.redis) {
      await this.redis.quit().catch(() => {});
    }
    this.memoryFallback.clear();
  }

  /**
   * Evaluates request against sliding window limit.
   */
  public async consume(
    prefix: string,
    key: string,
    limit: number,
    windowMs: number
  ): Promise<{
    allowed: boolean;
    remaining: number;
    resetInSeconds: number;
    totalHits: number;
    isAbusive: boolean;
  }> {
    const now = Date.now();
    const windowStart = now - windowMs;
    const redisKey = `ratelimit:${prefix}:${key}`;
    const abuseThreshold = limit * 5;

    if (this.redis && this.redis.status === 'ready') {
      try {
        // Redis Sorted Set sliding window algorithm:
        // 1. Remove entries older than windowStart
        // 2. Add current timestamp
        // 3. Count elements within the window
        // 4. Set expiration on key to windowMs
        const pipeline = this.redis.pipeline();
        pipeline.zremrangebyscore(redisKey, 0, windowStart);
        pipeline.zadd(redisKey, now, `${now}-${Math.random()}`);
        pipeline.zcard(redisKey);
        pipeline.pexpire(redisKey, windowMs);

        const results = await pipeline.exec();
        const count = (results?.[2]?.[1] as number) || 1;

        const allowed = count <= limit;
        const remaining = Math.max(0, limit - count);
        const resetInSeconds = Math.ceil(windowMs / 1000);
        const isAbusive = count >= abuseThreshold;

        return { allowed, remaining, resetInSeconds, totalHits: count, isAbusive };
      } catch (redisErr) {
        // Fall back to in-memory on redis operational error
      }
    }

    // In-memory sliding window fallback
    const timestamps = this.memoryFallback.get(redisKey) || [];
    const validTimestamps = timestamps.filter((t) => t > windowStart);
    validTimestamps.push(now);
    this.memoryFallback.set(redisKey, validTimestamps);

    // Periodically prune stale keys in fallback map
    if (this.memoryFallback.size > 10_000) {
      for (const [k, tsList] of this.memoryFallback.entries()) {
        if (tsList.length === 0 || (tsList[tsList.length - 1] ?? 0) < windowStart) {
          this.memoryFallback.delete(k);
        }
      }
    }

    const count = validTimestamps.length;
    const allowed = count <= limit;
    const remaining = Math.max(0, limit - count);
    const resetInSeconds = Math.ceil(windowMs / 1000);
    const isAbusive = count >= abuseThreshold;

    return { allowed, remaining, resetInSeconds, totalHits: count, isAbusive };
  }
}

// Singleton limiter instance
export const rateLimiterInstance = new SlidingWindowRateLimiter(env.REDIS_URL);

/**
 * Factory for creating Fastify preHandler hook for a specific route / policy
 */
export function createRateLimitHook(options: RateLimitOptions) {
  return async (req: FastifyRequest, reply: FastifyReply) => {
    const key = options.keyGenerator(req);
    const clientIp = getClientIp(req);

    const result = await rateLimiterInstance.consume(
      options.name,
      key,
      options.max,
      options.windowMs
    );

    // Set standard rate limiting headers
    reply.header('X-RateLimit-Limit', options.max);
    reply.header('X-RateLimit-Remaining', result.remaining);
    reply.header('X-RateLimit-Reset', result.resetInSeconds);

    if (result.isAbusive) {
      // SECURITY AUDIT LOG: High-frequency abuse detected
      req.log.warn({
        audit: true,
        eventType: 'RATE_LIMIT_ABUSE_DETECTED',
        rule: options.name,
        ip: clientIp,
        totalHits: result.totalHits,
        limit: options.max,
        url: req.raw.url,
      }, 'Potential automated attack or DDoS attempt detected');
    }

    if (!result.allowed) {
      reply.header('Retry-After', result.resetInSeconds);

      req.log.warn({
        audit: true,
        eventType: 'RATE_LIMIT_EXCEEDED',
        rule: options.name,
        ip: clientIp,
        totalHits: result.totalHits,
        limit: options.max,
        url: req.raw.url,
      }, 'Rate limit exceeded');

      return reply.status(429).send({
        statusCode: 429,
        error: 'Too Many Requests',
        message: 'Request rate limit exceeded. Please retry after the indicated interval.',
        retryAfter: result.resetInSeconds,
      });
    }
  };
}

/**
 * Pre-configured rate limiting hooks for common endpoint categories
 */
export const authRateLimiter = createRateLimitHook({
  name: 'auth',
  windowMs: RATE_LIMIT_TIERS.auth.windowMs,
  max: RATE_LIMIT_TIERS.auth.max,
  keyGenerator: keyGenerators.byIp,
});

export const uploadRateLimiter = createRateLimitHook({
  name: 'upload',
  windowMs: RATE_LIMIT_TIERS.upload.windowMs,
  max: RATE_LIMIT_TIERS.upload.max,
  keyGenerator: keyGenerators.byUserIdOrIp,
});

export const reportRateLimiter = createRateLimitHook({
  name: 'report',
  windowMs: RATE_LIMIT_TIERS.report.windowMs,
  max: RATE_LIMIT_TIERS.report.max,
  keyGenerator: keyGenerators.byUserIdOrIp,
});

/**
 * Global rate limiter Fastify plugin
 */
const globalRateLimiterPlugin: FastifyPluginAsync = async (fastify: FastifyInstance) => {
  await rateLimiterInstance.connect();

  fastify.addHook('onRequest', async (req: FastifyRequest, reply: FastifyReply) => {
    // Skip rate limiting on local health check
    if (req.url === '/health' || req.url === '/api/health') {
      return;
    }

    const key = keyGenerators.byIp(req);
    const result = await rateLimiterInstance.consume(
      'global',
      key,
      RATE_LIMIT_TIERS.global.max,
      RATE_LIMIT_TIERS.global.windowMs
    );

    reply.header('X-RateLimit-Limit', RATE_LIMIT_TIERS.global.max);
    reply.header('X-RateLimit-Remaining', result.remaining);
    reply.header('X-RateLimit-Reset', result.resetInSeconds);

    if (result.isAbusive) {
      req.log.warn({
        audit: true,
        eventType: 'GLOBAL_RATE_LIMIT_ABUSE',
        ip: getClientIp(req),
        totalHits: result.totalHits,
      }, 'Global rate limit severely exceeded');
    }

    if (!result.allowed) {
      reply.header('Retry-After', result.resetInSeconds);

      req.log.warn({
        audit: true,
        eventType: 'GLOBAL_RATE_LIMIT_EXCEEDED',
        ip: getClientIp(req),
        totalHits: result.totalHits,
      }, 'Global rate limit exceeded');

      return reply.status(429).send({
        statusCode: 429,
        error: 'Too Many Requests',
        message: 'Too many requests. Please slow down and try again later.',
        retryAfter: result.resetInSeconds,
      });
    }
  });

  fastify.addHook('onClose', async () => {
    await rateLimiterInstance.close();
  });
};

export const rateLimiter = fp(globalRateLimiterPlugin, {
  name: 'cyberguard-rate-limiter',
});
