/**
 * @file middleware.ts
 * @module auth/middleware
 * @description Production-grade Fastify authentication and Role-Based Access Control (RBAC) middleware.
 * Supports token extraction via Bearer headers and HttpOnly cookies, blacklist validation,
 * session freshness validation, role hierarchy, permission enforcement, and tamper-resistant audit logging.
 *
 * Security Rationale:
 * 1. Token Confidentiality: Access tokens extracted from Authorization headers or HttpOnly cookies
 *    are NEVER logged to console or audit trails.
 * 2. Defense in Depth: Validates both the cryptographic JWT signature AND active session state in Redis.
 * 3. Enforced MFA: Admin and Reviewer roles are strictly rejected if their session has not completed MFA.
 * 4. Principle of Least Privilege: Granular permission checks ensure users and staff cannot access
 *    sensitive review or administrative workflows.
 * 5. Failure Auditing: All failed authentication and authorization attempts are written to the audit log
 *    with sanitized metadata to detect potential credential stuffing or privilege escalation attacks.
 */

import type { FastifyRequest, FastifyReply } from 'fastify';
import type { TokenManager, UserRole } from './tokens.js';
import type { SessionManager } from './session.js';
import type { AuditLogger } from '../audit/logger.js';

// ============================================================================
// Types & Module Augmentation
// ============================================================================

export interface AuthenticatedUserContext {
  userId: string;
  role: UserRole;
  sessionId: string;
  mfaVerified: boolean;
  permissions: readonly string[];
}

declare module 'fastify' {
  interface FastifyRequest {
    user?: AuthenticatedUserContext;
  }
}

// ============================================================================
// RBAC & Permission Matrix
// ============================================================================

export type SystemPermission =
  | 'upload:create'
  | 'upload:read'
  | 'upload:delete'
  | 'upload:scan'
  | 'report:create'
  | 'report:read'
  | 'report:read_own'
  | 'report:review'
  | 'report:delete'
  | 'content:manage'
  | 'settings:manage'
  | 'admin:access'
  | 'user:manage'
  | 'audit:read'
  | 'audit:export';

const ROLE_PERMISSIONS: Record<UserRole, readonly string[]> = {
  admin: [
    'upload:create',
    'upload:read',
    'upload:delete',
    'upload:scan',
    'report:create',
    'report:read',
    'report:read_own',
    'report:review',
    'report:delete',
    'content:manage',
    'settings:manage',
    'admin:access',
    'user:manage',
    'audit:read',
    'audit:export',
  ],
  reviewer: [
    'upload:read',
    'upload:scan',
    'report:read',
    'report:review',
    'report:read_own',
  ],
  staff: [
    'upload:create',
    'upload:read',
    'report:read',
    'report:read_own',
    'content:manage',
  ],
  user: [
    'upload:create',
    'upload:read',
    'report:create',
    'report:read_own',
  ],
} as const;

// Roles that mandate verified MFA status before accessing protected endpoints
const MFA_MANDATORY_ROLES = new Set<UserRole>(['admin', 'reviewer']);

// ============================================================================
// Auth Middleware Factory
// ============================================================================

export interface AuthMiddlewareDependencies {
  tokenManager: TokenManager;
  sessionManager: SessionManager;
  auditLogger?: AuditLogger;
}

export class AuthMiddleware {
  private readonly tokenManager: TokenManager;
  private readonly sessionManager: SessionManager;
  private readonly auditLogger?: AuditLogger;

  constructor(deps: AuthMiddlewareDependencies) {
    this.tokenManager = deps.tokenManager;
    this.sessionManager = deps.sessionManager;
    this.auditLogger = deps.auditLogger;
  }

  /**
   * Extracts raw access token from Bearer Authorization header or HttpOnly cookie.
   */
  private extractToken(request: FastifyRequest): string | null {
    // 1. Check Authorization: Bearer <token>
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const parts = authHeader.split(' ');
      const tokenPart = parts[1]?.trim();
      if (parts.length === 2 && tokenPart && tokenPart.length > 0) {
        return tokenPart;
      }
    }

    // 2. Check HttpOnly cookie
    const cookies = (request as any).cookies;
    if (cookies && typeof cookies.access_token === 'string') {
      return cookies.access_token;
    }

    return null;
  }

  /**
   * Helper to log authentication and authorization failures without leaking sensitive credentials.
   */
  private async logSecurityFailure(
    request: FastifyRequest,
    action: 'AUTH_FAILED',
    reason: string,
    resource: string = request.url
  ): Promise<void> {
    if (!this.auditLogger) return;

    try {
      await this.auditLogger.log({
        actorId: request.user?.userId || 'ANONYMOUS',
        actorRole: request.user?.role || 'ANONYMOUS',
        action,
        resourceType: 'API_ENDPOINT',
        resourceId: resource,
        rawIpAddress: request.ip,
        userAgent: request.headers['user-agent'],
        outcome: 'denied',
        metadata: {
          path: request.url,
          method: request.method,
          reason,
        },
      });
    } catch {
      // Avoid failing request processing if audit sink has transient issue
    }
  }

  /**
   * Strict authentication preHandler hook.
   * Requires a valid, unrevoked JWT and active Redis session.
   */
  public authenticate = async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const rawToken = this.extractToken(request);

    if (!rawToken) {
      await this.logSecurityFailure(request, 'AUTH_FAILED', 'Missing authorization token');
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Authentication credentials are required',
      });
    }

    try {
      // 1. Verify JWT signature & expiration & blacklist
      const payload = await this.tokenManager.verifyAccessToken(rawToken);

      // 2. Verify Session exists and is active in Redis (idle & absolute timeout checks)
      const session = await this.sessionManager.validateSession(payload.sessionId);

      // 3. Enforce MFA requirement for sensitive roles
      if (MFA_MANDATORY_ROLES.has(payload.role) && !session.mfaVerified) {
        await this.logSecurityFailure(request, 'AUTH_FAILED', 'MFA verification required for privileged role');
        return reply.status(403).send({
          statusCode: 403,
          error: 'MFA_REQUIRED',
          message: 'Multi-factor authentication must be completed for this role.',
        });
      }

      // 4. Attach authenticated user context
      request.user = {
        userId: payload.sub,
        role: payload.role,
        sessionId: payload.sessionId,
        mfaVerified: session.mfaVerified,
        permissions: ROLE_PERMISSIONS[payload.role] || [],
      };
    } catch (err: any) {
      const errMsg = err?.message || 'Authentication failed';
      await this.logSecurityFailure(request, 'AUTH_FAILED', errMsg);

      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Invalid or expired authentication credentials',
      });
    }
  };

  /**
   * Optional authentication preHandler hook.
   * Attaches user context if a valid token exists, but does not block unauthenticated requests.
   */
  public optionalAuthenticate = async (request: FastifyRequest, _reply: FastifyReply): Promise<void> => {
    const rawToken = this.extractToken(request);
    if (!rawToken) return;

    try {
      const payload = await this.tokenManager.verifyAccessToken(rawToken);
      const session = await this.sessionManager.validateSession(payload.sessionId);

      request.user = {
        userId: payload.sub,
        role: payload.role,
        sessionId: payload.sessionId,
        mfaVerified: session.mfaVerified,
        permissions: ROLE_PERMISSIONS[payload.role] || [],
      };
    } catch {
      // In optional auth, invalid tokens simply leave request.user undefined
      request.user = undefined;
    }
  };

  /**
   * Role-based access control preHandler decorator factory.
   *
   * @param allowedRoles - List of acceptable UserRoles
   */
  public requireRole(...allowedRoles: UserRole[]) {
    return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
      // Run authentication first if not already performed
      if (!request.user) {
        await this.authenticate(request, reply);
        if (reply.sent) return;
      }

      const userRole = request.user!.role;
      if (!allowedRoles.includes(userRole)) {
        await this.logSecurityFailure(
          request,
          'AUTH_FAILED',
          `Insufficient role: requires one of [${allowedRoles.join(', ')}], user has [${userRole}]`
        );

        return reply.status(403).send({
          statusCode: 403,
          error: 'Forbidden',
          message: 'You do not have the required role to access this resource.',
        });
      }
    };
  }

  /**
   * Permission-based authorization preHandler decorator factory.
   *
   * @param requiredPermission - Granular permission required
   */
  public requirePermission(requiredPermission: SystemPermission) {
    return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
      // Run authentication first if not already performed
      if (!request.user) {
        await this.authenticate(request, reply);
        if (reply.sent) return;
      }

      const permissions = request.user!.permissions;
      if (!permissions.includes(requiredPermission)) {
        await this.logSecurityFailure(
          request,
          'AUTH_FAILED',
          `Missing permission: requires '${requiredPermission}'`
        );

        return reply.status(403).send({
          statusCode: 403,
          error: 'Forbidden',
          message: 'Access denied: insufficient permission.',
        });
      }
    };
  }
}
