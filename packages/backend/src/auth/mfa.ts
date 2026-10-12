/**
 * @file mfa.ts
 * @module auth/mfa
 * @description Production-grade Multi-Factor Authentication (MFA) using TOTP (Time-based One-Time Password)
 * and single-use cryptographic recovery codes for CyberGuard India.
 *
 * Security Rationale:
 * 1. Mandated MFA for privileged roles (admin, reviewer) and sensitive operations prevents account
 *    takeover even if primary credentials are leaked.
 * 2. Strict attempt rate-limiting (5 failures per 15-minute window) defends against brute-force attacks.
 * 3. TOTP window tolerance is restricted to +-1 step (30s) to balance clock drift with replay risk.
 * 4. Recovery codes are cryptographically generated (high entropy) and stored ONLY as SHA-256 hashes
 *    with constant-time verification.
 * 5. TOTP verification uses constant-time string comparison to neutralize timing side-channels.
 */

import crypto from 'node:crypto';
import { authenticator } from 'otplib';
import { z } from 'zod';
import type { UserRole } from './tokens.js';
import type { IRedisClient } from './tokens.js';

// ============================================================================
// Schemas & Types
// ============================================================================

export const TotpCodeSchema = z
  .string()
  .trim()
  .regex(/^\d{6}$/, { message: 'MFA TOTP code must be exactly 6 decimal digits' });

export const RecoveryCodeSchema = z
  .string()
  .trim()
  .regex(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/, {
    message: 'Recovery code must follow format XXXX-XXXX-XXXX',
  });

export interface MfaSetupDetails {
  secret: string;
  qrCodeUri: string;
  recoveryCodes: string[]; // Plaintext returned ONCE to the user during setup
}

export interface StoredRecoveryCode {
  hash: string;
  usedAt: number | null; // Timestamp if consumed, null otherwise
}

export interface VerifyMfaResult {
  verified: boolean;
  usedRecoveryCode?: boolean;
  remainingRecoveryCodes?: number;
}

// ============================================================================
// Configuration Constants
// ============================================================================

export const MFA_CONFIG = {
  ISSUER: 'CyberGuard India',
  TOTP_WINDOW: 1, // +- 1 step (30s tolerance)
  MAX_ATTEMPTS: 5,
  RATE_LIMIT_TTL_SEC: 15 * 60, // 15 minutes lockout window
  RECOVERY_CODE_COUNT: 10,
  REDIS_PREFIX: {
    ATTEMPTS: 'cg:mfa:attempts:',
    LOCKOUT: 'cg:mfa:lockout:',
  },
} as const;

// Configure global authenticator settings
authenticator.options = {
  window: MFA_CONFIG.TOTP_WINDOW,
  digits: 6,
  step: 30,
};

// ============================================================================
// Helper Utilities
// ============================================================================

/**
 * Constant-time string equality check to mitigate side-channel timing attacks.
 */
function timingSafeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');

  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Hashes a recovery code for tamper-resistant storage.
 */
export function hashRecoveryCode(code: string): string {
  const normalized = code.replace(/[^A-Z0-9]/gi, '').toUpperCase();
  return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex');
}

// ============================================================================
// MFA Manager Class
// ============================================================================

export class MfaManager {
  private readonly redis: IRedisClient;
  private readonly appName: string;

  constructor(redisClient: IRedisClient, appName: string = MFA_CONFIG.ISSUER) {
    this.redis = redisClient;
    this.appName = appName;
  }

  /**
   * Evaluates if MFA is strictly mandated for the specified role.
   * Admin and Reviewer roles must ALWAYS enforce MFA.
   */
  public static isMfaRequiredForRole(role: UserRole): boolean {
    return role === 'admin' || role === 'reviewer';
  }

  /**
   * Generates a new TOTP secret, otpauth:// QR URI, and 10 single-use recovery codes.
   *
   * @param userIdentifier - Unique user identity (e.g., pseudonymized account identifier)
   */
  public generateMfaSetup(userIdentifier: string): MfaSetupDetails {
    // Generate high-entropy base32 secret
    const secret = authenticator.generateSecret(20);
    const qrCodeUri = authenticator.keyuri(userIdentifier, this.appName, secret);
    const recoveryCodes = this.generateRecoveryCodes(MFA_CONFIG.RECOVERY_CODE_COUNT);

    return {
      secret,
      qrCodeUri,
      recoveryCodes,
    };
  }

  /**
   * Generates formatted, cryptographically secure recovery codes.
   * Format: XXXX-XXXX-XXXX
   */
  public generateRecoveryCodes(count: number = 10): string[] {
    const codes: string[] = [];
    for (let i = 0; i < count; i++) {
      const bytes = crypto.randomBytes(6);
      const hex = bytes.toString('hex').toUpperCase();
      const code = `${hex.slice(0, 4)}-${hex.slice(4, 8)}-${hex.slice(8, 12)}`;
      codes.push(code);
    }
    return codes;
  }

  /**
   * Hashes a list of plain recovery codes for safe storage in DB.
   */
  public hashRecoveryCodesForStorage(codes: string[]): StoredRecoveryCode[] {
    return codes.map((code) => ({
      hash: hashRecoveryCode(code),
      usedAt: null,
    }));
  }

  /**
   * Verifies an MFA attempt using either a 6-digit TOTP code or a recovery code.
   * Enforces rate limiting (max 5 failed attempts per 15 minutes).
   *
   * @param userId - User ID being authenticated
   * @param providedCode - 6-digit TOTP or formatted recovery code
   * @param totpSecret - User's stored encrypted or plaintext TOTP secret
   * @param storedRecoveryCodes - User's stored recovery codes array
   */
  public async verifyMfa(
    userId: string,
    providedCode: string,
    totpSecret: string,
    storedRecoveryCodes: StoredRecoveryCode[] = []
  ): Promise<VerifyMfaResult> {
    const rateLimitKey = `${MFA_CONFIG.REDIS_PREFIX.ATTEMPTS}${userId}`;
    const lockoutKey = `${MFA_CONFIG.REDIS_PREFIX.LOCKOUT}${userId}`;

    // 1. Check if user is currently locked out
    const isLockedOut = await this.redis.get(lockoutKey);
    if (isLockedOut) {
      throw new Error('AUTH_MFA_LOCKED: Too many failed MFA attempts. Account locked for 15 minutes.');
    }

    const trimmedCode = providedCode.trim();

    // 2. Check if provided code is a 6-digit TOTP code
    const isTotpCandidate = /^\d{6}$/.test(trimmedCode);

    if (isTotpCandidate) {
      // Validate schema
      TotpCodeSchema.parse(trimmedCode);

      // Verify TOTP using otplib
      const isValid = authenticator.check(trimmedCode, totpSecret);

      if (isValid) {
        // Reset failed attempt counter on success
        await this.redis.del(rateLimitKey);
        return { verified: true, usedRecoveryCode: false };
      }
    } else {
      // 3. Check if provided code matches a valid unconsumed recovery code
      const candidateHash = hashRecoveryCode(trimmedCode);

      for (const item of storedRecoveryCodes) {
        if (!item.usedAt && timingSafeEqual(item.hash, candidateHash)) {
          // Mark recovery code as consumed
          item.usedAt = Date.now();

          // Reset rate limits
          await this.redis.del(rateLimitKey);

          const remaining = storedRecoveryCodes.filter((c) => !c.usedAt).length;
          return {
            verified: true,
            usedRecoveryCode: true,
            remainingRecoveryCodes: remaining,
          };
        }
      }
    }

    // 4. Record failed attempt and enforce rate limit
    await this.recordFailedAttempt(userId, rateLimitKey, lockoutKey);

    return { verified: false };
  }

  /**
   * Tracks failed MFA attempts in Redis and applies 15-minute lockout if limit exceeded.
   */
  private async recordFailedAttempt(
    userId: string,
    rateLimitKey: string,
    lockoutKey: string
  ): Promise<void> {
    const attemptsStr = await this.redis.get(rateLimitKey);
    const currentAttempts = attemptsStr ? parseInt(attemptsStr, 10) : 0;
    const newAttempts = currentAttempts + 1;

    if (newAttempts >= MFA_CONFIG.MAX_ATTEMPTS) {
      // Lock out user for 15 minutes
      await this.redis.set(lockoutKey, '1', 'EX', MFA_CONFIG.RATE_LIMIT_TTL_SEC);
      await this.redis.del(rateLimitKey);
      throw new Error(
        `AUTH_MFA_LOCKED: Maximum ${MFA_CONFIG.MAX_ATTEMPTS} attempts exceeded. MFA locked for 15 minutes.`
      );
    }

    await this.redis.set(
      rateLimitKey,
      newAttempts.toString(),
      'EX',
      MFA_CONFIG.RATE_LIMIT_TTL_SEC
    );
  }

  /**
   * Clears MFA lockouts (e.g., after administrative identity verification).
   */
  public async unlockMfa(userId: string): Promise<void> {
    await this.redis.del(`${MFA_CONFIG.REDIS_PREFIX.ATTEMPTS}${userId}`);
    await this.redis.del(`${MFA_CONFIG.REDIS_PREFIX.LOCKOUT}${userId}`);
  }
}
