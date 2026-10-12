/**
 * @file tokens.ts
 * @module auth/tokens
 * @description Production-grade JWT and refresh token lifecycle management for CyberGuard India.
 * Implements short-lived access tokens, cryptographic rotation, Redis revocation blacklists,
 * and constant-time token comparison following OWASP and CERT-In security guidelines.
 *
 * Security Rationale:
 * 1. Short-lived access tokens (15 minutes) minimize the exposure window if a token is intercepted.
 * 2. Strict adherence to non-PII claims prevents data leakage in logs or client-side storage.
 * 3. Constant-time comparison prevents timing attacks when comparing sensitive token hashes.
 * 4. Token rotation generates a new refresh token family member on each use while invalidating
 *    the old one. If reuse is detected, the entire session family is revoked.
 * 5. Redis blacklisting provides near-instantaneous token invalidation before expiry.
 */

import crypto from 'node:crypto';
import jwt, { type SignOptions, type VerifyOptions } from 'jsonwebtoken';
import { z } from 'zod';

// ============================================================================
// Types & Schemas
// ============================================================================

export const UserRoleSchema = z.enum(['admin', 'reviewer', 'staff', 'user']);
export type UserRole = z.infer<typeof UserRoleSchema>;

/**
 * Access token payload schema.
 * Strictly forbids PII (no names, phone numbers, email addresses, or Aadhaar numbers).
 */
export const AccessTokenPayloadSchema = z.object({
  sub: z.string().uuid({ message: 'Subject (userId) must be a valid UUID' }),
  role: UserRoleSchema,
  sessionId: z.string().uuid({ message: 'Session ID must be a valid UUID' }),
  iat: z.number().int().nonnegative(),
  exp: z.number().int().positive(),
  iss: z.string().default('cyberguard-india'),
  aud: z.string().default('cyberguard-india-api'),
});

export type AccessTokenPayload = z.infer<typeof AccessTokenPayloadSchema>;

/**
 * Input parameters required to mint a new access token.
 */
export interface MintAccessTokenParams {
  userId: string;
  role: UserRole;
  sessionId: string;
}

/**
 * Refresh token metadata stored in Redis.
 */
export interface RefreshTokenMetadata {
  tokenId: string;
  userId: string;
  sessionId: string;
  deviceFingerprintHash: string;
  createdAt: number;
  expiresAt: number;
  familyId: string;
  isRevoked: boolean;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  expiresIn: number; // Seconds (900 for 15 mins)
}

/**
 * Minimal Redis interface required by token management to avoid tight coupling.
 */
export interface IRedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, mode?: string, duration?: number): Promise<unknown>;
  del(key: string | string[]): Promise<number>;
  keys(pattern: string): Promise<string[]>;
  expire(key: string, seconds: number): Promise<number>;
}

// ============================================================================
// Configuration Defaults & Constants
// ============================================================================

export const TOKEN_CONFIG = {
  ACCESS_TOKEN_TTL_SEC: 15 * 60, // 15 minutes
  REFRESH_TOKEN_TTL_SEC: 7 * 24 * 60 * 60, // 7 days
  ISSUER: 'cyberguard-india',
  AUDIENCE: 'cyberguard-india-api',
  ALGORITHM: 'HS256' as jwt.Algorithm, // Can also support RS256 if private/public keys supplied
  REDIS_PREFIX: {
    BLACKLIST: 'cg:blacklist:token:',
    REFRESH: 'cg:refresh:token:',
    USER_SESSIONS: 'cg:user:sessions:',
  },
} as const;

// ============================================================================
// Helper Utilities
// ============================================================================

/**
 * Perform constant-time string comparison to prevent timing attacks.
 *
 * @param a - First string (e.g. provided token or hash)
 * @param b - Second string (e.g. stored token or hash)
 * @returns boolean indicating strict equality
 */
export function timingSafeEqualString(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  if (bufA.length !== bufB.length) {
    // Return false, but do dummy comparison to normalize timing profile
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }

  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Hash high-entropy identifiers (like device fingerprints or refresh tokens)
 * before persisting or indexing them.
 */
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

// ============================================================================
// Token Manager Class
// ============================================================================

export class TokenManager {
  private readonly secretOrKey: string;
  private readonly publicKey?: string;
  private readonly algorithm: jwt.Algorithm;
  private readonly redis: IRedisClient;

  /**
   * Initializes the TokenManager.
   *
   * @param options.jwtSecret - Symmetric secret (HS256) or Private Key (RS256)
   * @param options.publicKey - Optional public key if using RS256
   * @param options.redisClient - Connected Redis client
   * @param options.algorithm - JWT algorithm ('HS256' | 'RS256')
   */
  constructor(options: {
    jwtSecret: string;
    publicKey?: string;
    redisClient: IRedisClient;
    algorithm?: jwt.Algorithm;
  }) {
    if (!options.jwtSecret || options.jwtSecret.length < 32) {
      throw new Error('SECURITY CONFIGURATION ERROR: JWT secret must be at least 32 characters long');
    }

    this.secretOrKey = options.jwtSecret;
    this.publicKey = options.publicKey;
    this.algorithm = options.algorithm ?? TOKEN_CONFIG.ALGORITHM;
    this.redis = options.redisClient;
  }

  /**
   * Generates a short-lived (15 min) JWT Access Token.
   * Never embeds PII; strictly validates parameters with Zod.
   */
  public generateAccessToken(params: MintAccessTokenParams): string {
    const validated = z
      .object({
        userId: z.string().uuid(),
        role: UserRoleSchema,
        sessionId: z.string().uuid(),
      })
      .parse(params);

    const now = Math.floor(Date.now() / 1000);
    const payload = {
      sub: validated.userId,
      role: validated.role,
      sessionId: validated.sessionId,
      iss: TOKEN_CONFIG.ISSUER,
      aud: TOKEN_CONFIG.AUDIENCE,
    };

    const signOptions: SignOptions = {
      algorithm: this.algorithm,
      expiresIn: TOKEN_CONFIG.ACCESS_TOKEN_TTL_SEC,
      jwtid: crypto.randomUUID(), // unique jti for individual token tracking
      notBefore: 0,
    };

    return jwt.sign(payload, this.secretOrKey, signOptions);
  }

  /**
   * Generates an opaque cryptographically secure Refresh Token and stores
   * its metadata in Redis associated with the user and device fingerprint.
   *
   * @param userId - User UUID
   * @param sessionId - Session UUID
   * @param deviceFingerprint - Device fingerprint raw string (will be hashed)
   * @param familyId - Optional existing refresh token family ID for rotation tracking
   */
  public async generateRefreshToken(
    userId: string,
    sessionId: string,
    deviceFingerprint: string,
    familyId?: string
  ): Promise<string> {
    const rawTokenBytes = crypto.randomBytes(48).toString('base64url');
    const tokenId = crypto.randomUUID();
    const tokenHash = hashToken(rawTokenBytes);
    const assignedFamilyId = familyId || crypto.randomUUID();
    const now = Math.floor(Date.now() / 1000);

    const metadata: RefreshTokenMetadata = {
      tokenId,
      userId,
      sessionId,
      deviceFingerprintHash: hashToken(deviceFingerprint),
      createdAt: now,
      expiresAt: now + TOKEN_CONFIG.REFRESH_TOKEN_TTL_SEC,
      familyId: assignedFamilyId,
      isRevoked: false,
    };

    // Store in Redis indexed by hash
    const redisKey = `${TOKEN_CONFIG.REDIS_PREFIX.REFRESH}${tokenHash}`;
    await this.redis.set(
      redisKey,
      JSON.stringify(metadata),
      'EX',
      TOKEN_CONFIG.REFRESH_TOKEN_TTL_SEC
    );

    return `${tokenId}.${rawTokenBytes}`;
  }

  /**
   * Issues both Access and Refresh tokens simultaneously (e.g. at login).
   */
  public async createTokenPair(
    userId: string,
    role: UserRole,
    sessionId: string,
    deviceFingerprint: string
  ): Promise<TokenPair> {
    const accessToken = this.generateAccessToken({ userId, role, sessionId });
    const refreshToken = await this.generateRefreshToken(userId, sessionId, deviceFingerprint);

    return {
      accessToken,
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: TOKEN_CONFIG.ACCESS_TOKEN_TTL_SEC,
    };
  }

  /**
   * Verifies and decodes an Access Token, verifying signature and checking Redis blacklist.
   */
  public async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    const verifyKey = this.publicKey || this.secretOrKey;
    const verifyOptions: VerifyOptions = {
      algorithms: [this.algorithm],
      issuer: TOKEN_CONFIG.ISSUER,
      audience: TOKEN_CONFIG.AUDIENCE,
    };

    let decodedUnknown: unknown;
    try {
      decodedUnknown = jwt.verify(token, verifyKey, verifyOptions);
    } catch (err: unknown) {
      if (err instanceof jwt.TokenExpiredError) {
        throw new Error('AUTH_TOKEN_EXPIRED: Access token has expired');
      }
      throw new Error('AUTH_TOKEN_INVALID: Invalid access token signature or format');
    }

    const parsed = AccessTokenPayloadSchema.safeParse(decodedUnknown);
    if (!parsed.success) {
      throw new Error('AUTH_TOKEN_MALFORMED: Access token claims are invalid');
    }

    const payload = parsed.data;

    // Check blacklist (e.g., if revoked before expiration)
    const tokenHash = hashToken(token);
    const isBlacklisted = await this.redis.get(`${TOKEN_CONFIG.REDIS_PREFIX.BLACKLIST}${tokenHash}`);
    if (isBlacklisted) {
      throw new Error('AUTH_TOKEN_REVOKED: Token has been revoked');
    }

    return payload;
  }

  /**
   * Rotates a refresh token: verifies current token, revokes it, validates device fingerprint,
   * detects token reuse, and generates a new pair.
   */
  public async rotateRefreshToken(
    providedRefreshToken: string,
    role: UserRole,
    currentDeviceFingerprint: string
  ): Promise<TokenPair> {
    const parts = providedRefreshToken.split('.');
    if (parts.length !== 2) {
      throw new Error('AUTH_REFRESH_INVALID: Malformed refresh token structure');
    }

    const [, rawBytes] = parts;
    if (!rawBytes) {
      throw new Error('AUTH_REFRESH_INVALID: Malformed refresh token structure');
    }
    const tokenHash = hashToken(rawBytes);
    const redisKey = `${TOKEN_CONFIG.REDIS_PREFIX.REFRESH}${tokenHash}`;

    const metadataRaw = await this.redis.get(redisKey);
    if (!metadataRaw) {
      throw new Error('AUTH_REFRESH_NOT_FOUND: Refresh token not found or already consumed');
    }

    const metadata: RefreshTokenMetadata = JSON.parse(metadataRaw);

    // Reuse detection: If token was already revoked, family is compromised!
    if (metadata.isRevoked) {
      // Invalidate all tokens for this session immediately
      await this.revokeSession(metadata.sessionId);
      throw new Error('AUTH_REFRESH_COMPROMISED: Token reuse detected. Session terminated for security.');
    }

    // Verify device fingerprint hash with constant-time equality
    const expectedFingerprintHash = hashToken(currentDeviceFingerprint);
    if (!timingSafeEqualString(metadata.deviceFingerprintHash, expectedFingerprintHash)) {
      // Possible session hijacking attempt
      await this.revokeSession(metadata.sessionId);
      throw new Error('AUTH_FINGERPRINT_MISMATCH: Device fingerprint changed during refresh.');
    }

    // Immediately mark old token as revoked in Redis to avoid race conditions
    metadata.isRevoked = true;
    const remainingTtl = Math.max(1, metadata.expiresAt - Math.floor(Date.now() / 1000));
    await this.redis.set(redisKey, JSON.stringify(metadata), 'EX', remainingTtl);

    // Generate new Access and Refresh tokens under the same family
    const newAccessToken = this.generateAccessToken({
      userId: metadata.userId,
      role,
      sessionId: metadata.sessionId,
    });

    const newRefreshToken = await this.generateRefreshToken(
      metadata.userId,
      metadata.sessionId,
      currentDeviceFingerprint,
      metadata.familyId
    );

    return {
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      tokenType: 'Bearer',
      expiresIn: TOKEN_CONFIG.ACCESS_TOKEN_TTL_SEC,
    };
  }

  /**
   * Revokes an active access token by adding its hash to the Redis blacklist.
   * TTL is matched to the remaining lifetime of the token.
   */
  public async blacklistAccessToken(token: string): Promise<void> {
    try {
      const decoded = jwt.decode(token) as { exp?: number } | null;
      const now = Math.floor(Date.now() / 1000);
      const ttl = decoded?.exp && decoded.exp > now ? decoded.exp - now : TOKEN_CONFIG.ACCESS_TOKEN_TTL_SEC;

      const tokenHash = hashToken(token);
      await this.redis.set(
        `${TOKEN_CONFIG.REDIS_PREFIX.BLACKLIST}${tokenHash}`,
        'revoked',
        'EX',
        ttl
      );
    } catch {
      // Gracefully handle un-decodable tokens
    }
  }

  /**
   * Revokes an individual refresh token.
   */
  public async revokeRefreshToken(refreshToken: string): Promise<void> {
    const parts = refreshToken.split('.');
    const part1 = parts[1];
    if (parts.length === 2 && part1) {
      const tokenHash = hashToken(part1);
      await this.redis.del(`${TOKEN_CONFIG.REDIS_PREFIX.REFRESH}${tokenHash}`);
    }
  }

  /**
   * Revokes all tokens associated with a given session ID.
   */
  public async revokeSession(sessionId: string): Promise<void> {
    const keys = await this.redis.keys(`${TOKEN_CONFIG.REDIS_PREFIX.REFRESH}*`);
    for (const key of keys) {
      const val = await this.redis.get(key);
      if (val) {
        try {
          const meta: RefreshTokenMetadata = JSON.parse(val);
          if (meta.sessionId === sessionId) {
            await this.redis.del(key);
          }
        } catch {
          // Continue if single entry fails to parse
        }
      }
    }
  }

  /**
   * Revokes all active tokens and sessions for a user across all devices.
   */
  public async revokeAllUserTokens(userId: string): Promise<void> {
    const keys = await this.redis.keys(`${TOKEN_CONFIG.REDIS_PREFIX.REFRESH}*`);
    for (const key of keys) {
      const val = await this.redis.get(key);
      if (val) {
        try {
          const meta: RefreshTokenMetadata = JSON.parse(val);
          if (meta.userId === userId) {
            await this.redis.del(key);
          }
        } catch {
          // Ignore parse errors
        }
      }
    }
  }
}
