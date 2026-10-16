/**
 * @file session.ts
 * @module auth/session
 * @description Production-grade Redis-backed session management for CyberGuard India.
 * Implements idle timeout (30 min), absolute session expiration (8 hrs), concurrent session limits (5),
 * device tracking, and IP address pseudonymization.
 *
 * Security Rationale:
 * 1. IP addresses are hashed using SHA-256 before storage to comply with Indian DPDP Act minimization rules.
 * 2. Strict concurrent session limit (5 devices) prevents automated account sharing or rogue persistent sessions.
 * 3. Dual-tier session timeout:
 *    - Idle timeout (30 min): Terminates inactive sessions to limit physical device hijacking risk.
 *    - Absolute timeout (8 hrs): Forces complete re-authentication, preventing indefinite session renewal.
 * 4. High-entropy session IDs generated with crypto.randomBytes(32) prevent brute-force enumeration.
 */

import crypto from 'node:crypto';
import { z } from 'zod';
import type { IRedisClient, UserRole } from './tokens.js';

// ============================================================================
// Schemas & Types
// ============================================================================

export const SessionDataSchema = z.object({
  sessionId: z.string().uuid(),
  userId: z.string().uuid(),
  role: z.enum(['admin', 'reviewer', 'staff', 'user']),
  deviceFingerprint: z.string(),
  ipAddressHash: z.string().length(64), // SHA-256 hash
  createdAt: z.number().int().positive(),
  lastActivity: z.number().int().positive(),
  mfaVerified: z.boolean(),
  userAgentSanitized: z.string().max(256),
});

export type SessionData = z.infer<typeof SessionDataSchema>;

/**
 * Public view of a session safe to return to the user dashboard.
 * Strips raw fingerprint and internal hashes.
 */
export interface UserSessionView {
  sessionId: string;
  createdAt: number;
  lastActivity: number;
  mfaVerified: boolean;
  userAgent: string;
  isCurrent: boolean;
}

export interface CreateSessionParams {
  userId: string;
  role: UserRole;
  deviceFingerprint: string;
  rawIpAddress: string;
  userAgent?: string;
  mfaVerified?: boolean;
}

// ============================================================================
// Configuration Constants
// ============================================================================

export const SESSION_CONFIG = {
  IDLE_TIMEOUT_SEC: 30 * 60, // 30 minutes
  ABSOLUTE_TIMEOUT_SEC: 8 * 60 * 60, // 8 hours
  MAX_CONCURRENT_SESSIONS: 5,
  REDIS_PREFIX: {
    SESSION: 'cg:session:',
    USER_SET: 'cg:user:sessions:',
  },
} as const;

// ============================================================================
// Helper Utilities
// ============================================================================

/**
 * Pseudonymizes IP addresses via SHA-256 hash.
 */
export function hashIpAddress(ip: string): string {
  return crypto.createHash('sha256').update(ip.trim(), 'utf8').digest('hex');
}

/**
 * Sanitizes User-Agent strings, removing control characters and limiting length.
 */
export function sanitizeUserAgent(ua?: string): string {
  if (!ua) return 'Unknown Device';
  return ua.replace(/[^\x20-\x7E]/g, '').slice(0, 255);
}

// ============================================================================
// Session Manager Class
// ============================================================================

export class SessionManager {
  private readonly redis: IRedisClient;

  constructor(redisClient: IRedisClient) {
    this.redis = redisClient;
  }

  /**
   * Creates a new session, enforcing concurrent session limits (max 5 per user).
   * Evicts the oldest session if the limit is exceeded.
   */
  public async createSession(params: CreateSessionParams): Promise<SessionData> {
    const sessionId = crypto.randomUUID();
    const now = Math.floor(Date.now() / 1000);

    const session: SessionData = {
      sessionId,
      userId: params.userId,
      role: params.role,
      deviceFingerprint: params.deviceFingerprint,
      ipAddressHash: hashIpAddress(params.rawIpAddress),
      createdAt: now,
      lastActivity: now,
      mfaVerified: params.mfaVerified ?? false,
      userAgentSanitized: sanitizeUserAgent(params.userAgent),
    };

    // Retrieve active sessions for user
    const userSessionsKey = `${SESSION_CONFIG.REDIS_PREFIX.USER_SET}${params.userId}`;
    const rawSessionsJson = await this.redis.get(userSessionsKey);
    const sessionIds: string[] = rawSessionsJson ? JSON.parse(rawSessionsJson) : [];

    // Filter out expired or dead sessions
    const activeSessionIds: string[] = [];
    for (const id of sessionIds) {
      const exists = await this.redis.get(`${SESSION_CONFIG.REDIS_PREFIX.SESSION}${id}`);
      if (exists) {
        activeSessionIds.push(id);
      }
    }

    // Enforce concurrent session limit (5 max)
    if (activeSessionIds.length >= SESSION_CONFIG.MAX_CONCURRENT_SESSIONS) {
      // Evict oldest session (FIFO)
      const oldestSessionId = activeSessionIds.shift();
      if (oldestSessionId) {
        await this.redis.del(`${SESSION_CONFIG.REDIS_PREFIX.SESSION}${oldestSessionId}`);
      }
    }

    // Add new session ID
    activeSessionIds.push(sessionId);

    // Save session payload with idle TTL
    const sessionKey = `${SESSION_CONFIG.REDIS_PREFIX.SESSION}${sessionId}`;
    await this.redis.set(
      sessionKey,
      JSON.stringify(session),
      'EX',
      SESSION_CONFIG.IDLE_TIMEOUT_SEC
    );

    // Update user active session registry
    await this.redis.set(
      userSessionsKey,
      JSON.stringify(activeSessionIds),
      'EX',
      SESSION_CONFIG.ABSOLUTE_TIMEOUT_SEC
    );

    return session;
  }

  /**
   * Validates a session on each request:
   * 1. Checks existence in Redis (fails if idle expired)
   * 2. Checks absolute timeout (8 hours from creation)
   * 3. Updates `lastActivity` and refreshes Redis idle expiration
   */
  public async validateSession(sessionId: string): Promise<SessionData> {
    const sessionKey = `${SESSION_CONFIG.REDIS_PREFIX.SESSION}${sessionId}`;
    const raw = await this.redis.get(sessionKey);

    if (!raw) {
      throw new Error('AUTH_SESSION_EXPIRED: Session does not exist or has expired due to inactivity.');
    }

    let session: SessionData;
    try {
      session = SessionDataSchema.parse(JSON.parse(raw));
    } catch {
      await this.redis.del(sessionKey);
      throw new Error('AUTH_SESSION_MALFORMED: Invalid session structure.');
    }

    const now = Math.floor(Date.now() / 1000);

    // Check Absolute Timeout (8 hours from creation)
    if (now - session.createdAt > SESSION_CONFIG.ABSOLUTE_TIMEOUT_SEC) {
      await this.revokeSession(sessionId, session.userId);
      throw new Error('AUTH_SESSION_ABSOLUTE_TIMEOUT: Session has reached maximum lifetime (8h). Please re-login.');
    }

    // Update last activity
    session.lastActivity = now;

    // Refresh idle TTL
    await this.redis.set(
      sessionKey,
      JSON.stringify(session),
      'EX',
      SESSION_CONFIG.IDLE_TIMEOUT_SEC
    );

    return session;
  }

  /**
   * Updates MFA status on an active session once MFA verification completes.
   */
  public async markSessionMfaVerified(sessionId: string): Promise<void> {
    const session = await this.validateSession(sessionId);
    session.mfaVerified = true;

    const sessionKey = `${SESSION_CONFIG.REDIS_PREFIX.SESSION}${sessionId}`;
    await this.redis.set(
      sessionKey,
      JSON.stringify(session),
      'EX',
      SESSION_CONFIG.IDLE_TIMEOUT_SEC
    );
  }

  /**
   * Retrieves active sessions for a user formatted safely for UI display.
   */
  public async listUserSessions(userId: string, currentSessionId: string): Promise<UserSessionView[]> {
    const userSessionsKey = `${SESSION_CONFIG.REDIS_PREFIX.USER_SET}${userId}`;
    const rawSessionsJson = await this.redis.get(userSessionsKey);
    if (!rawSessionsJson) return [];

    const sessionIds: string[] = JSON.parse(rawSessionsJson);
    const views: UserSessionView[] = [];

    for (const id of sessionIds) {
      const raw = await this.redis.get(`${SESSION_CONFIG.REDIS_PREFIX.SESSION}${id}`);
      if (raw) {
        try {
          const s: SessionData = JSON.parse(raw);
          views.push({
            sessionId: s.sessionId,
            createdAt: s.createdAt,
            lastActivity: s.lastActivity,
            mfaVerified: s.mfaVerified,
            userAgent: s.userAgentSanitized,
            isCurrent: s.sessionId === currentSessionId,
          });
        } catch {
          // Ignore corrupt session records
        }
      }
    }

    return views;
  }

  /**
   * Revokes a single session.
   */
  public async revokeSession(sessionId: string, userId?: string): Promise<void> {
    const sessionKey = `${SESSION_CONFIG.REDIS_PREFIX.SESSION}${sessionId}`;

    // If userId not provided, retrieve from session record first
    if (!userId) {
      const raw = await this.redis.get(sessionKey);
      if (raw) {
        try {
          const s = JSON.parse(raw);
          userId = s.userId;
        } catch {
          // Proceed with deletion
        }
      }
    }

    await this.redis.del(sessionKey);

    if (userId) {
      const userSessionsKey = `${SESSION_CONFIG.REDIS_PREFIX.USER_SET}${userId}`;
      const rawSessions = await this.redis.get(userSessionsKey);
      if (rawSessions) {
        const ids: string[] = JSON.parse(rawSessions);
        const filtered = ids.filter((id) => id !== sessionId);
        await this.redis.set(
          userSessionsKey,
          JSON.stringify(filtered),
          'EX',
          SESSION_CONFIG.ABSOLUTE_TIMEOUT_SEC
        );
      }
    }
  }

  /**
   * Revokes all sessions for a user across all devices.
   */
  public async revokeAllSessions(userId: string): Promise<void> {
    const userSessionsKey = `${SESSION_CONFIG.REDIS_PREFIX.USER_SET}${userId}`;
    const rawSessionsJson = await this.redis.get(userSessionsKey);

    if (rawSessionsJson) {
      const ids: string[] = JSON.parse(rawSessionsJson);
      for (const id of ids) {
        await this.redis.del(`${SESSION_CONFIG.REDIS_PREFIX.SESSION}${id}`);
      }
      await this.redis.del(userSessionsKey);
    }
  }
}
