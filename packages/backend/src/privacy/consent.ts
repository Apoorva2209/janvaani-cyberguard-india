/**
 * @file consent.ts
 * @module privacy/consent
 * @description Production-grade consent management service compliant with the Digital Personal Data
 * Protection (DPDP) Act, 2023 of India. Handles explicit consent capture, multi-version tracking,
 * granular consents (AI processing, external translation), immediate withdrawal enforcement,
 * and immutable consent audit trails.
 *
 * Security & Compliance Rationale:
 * 1. DPDP Act Section 6 Notice & Consent: Consent must be free, specific, informed, unconditional,
 *    and unambiguous with clear affirmative action.
 * 2. Unbundled Consent: AI processing and external translation cannot be bundled into generic Terms of Service;
 *    they require independent explicit opting-in.
 * 3. Right to Withdraw (Section 6(4)): Users can withdraw consent at any time as easily as giving it.
 *    Withdrawal immediately stops downstream processing and triggers retention cleanup where applicable.
 * 4. Pseudonymized Records: Network IP addresses associated with consent timestamps are stored as SHA-256 hashes.
 */

import crypto from 'node:crypto';
import { z } from 'zod';
import type { AuditLogger } from '../audit/logger.js';

// ============================================================================
// Types & Schemas
// ============================================================================

export const ConsentTypeSchema = z.enum([
  'PRIVACY_POLICY',
  'TERMS_OF_SERVICE',
  'AI_PROCESSING',
  'EXTERNAL_TRANSLATION',
  'DATA_RETENTION',
  'MARKETING',
]);

export type ConsentType = z.infer<typeof ConsentTypeSchema>;

export const ConsentRecordSchema = z.object({
  id: z.string().uuid(),
  userId: z.string().uuid(),
  consentType: ConsentTypeSchema,
  version: z.string().min(1),
  grantedAt: z.number().int().positive(),
  withdrawnAt: z.number().int().positive().nullable(),
  ipAddressHash: z.string().length(64),
  metadata: z.record(z.any()).optional(),
});

export type ConsentRecord = z.infer<typeof ConsentRecordSchema>;

export interface RecordConsentParams {
  userId: string;
  consentType: ConsentType;
  version: string;
  rawIpAddress?: string;
  metadata?: Record<string, unknown>;
}

export interface ConsentStatusResult {
  hasConsent: boolean;
  version?: string;
  requiresRePrompt: boolean;
  currentActiveVersion: string;
}

export interface IPrismaConsentClient {
  userConsent: {
    findFirst(args: {
      where: {
        userId: string;
        consentType: ConsentType;
        withdrawnAt: null;
      };
      orderBy?: { grantedAt: 'desc' };
    }): Promise<ConsentRecord | null>;
    findMany(args: {
      where: { userId?: string; consentType?: ConsentType };
      orderBy?: { grantedAt: 'desc' };
    }): Promise<ConsentRecord[]>;
    create(args: { data: ConsentRecord }): Promise<ConsentRecord>;
    update(args: {
      where: { id: string };
      data: { withdrawnAt: number };
    }): Promise<ConsentRecord>;
    updateMany(args: {
      where: { userId: string; consentType: ConsentType; withdrawnAt: null };
      data: { withdrawnAt: number };
    }): Promise<{ count: number }>;
  };
}

// ============================================================================
// Active Policy Versions Registry
// ============================================================================

/**
 * Minimum active legal versions required for the platform.
 * If user has consented to an older version, system prompts for renewed consent.
 */
export const ACTIVE_POLICY_VERSIONS: Record<ConsentType, string> = {
  PRIVACY_POLICY: 'v2026.1',
  TERMS_OF_SERVICE: 'v2026.1',
  AI_PROCESSING: 'v2026.1',
  EXTERNAL_TRANSLATION: 'v2026.1',
  DATA_RETENTION: 'v2026.1',
  MARKETING: 'v2026.1',
};

// ============================================================================
// Consent Manager Implementation
// ============================================================================

export class ConsentManager {
  private readonly prisma?: IPrismaConsentClient;
  private readonly auditLogger?: AuditLogger;
  // In-memory store fallback when running without direct DB connection
  private inMemoryStore: Map<string, ConsentRecord> = new Map();

  constructor(options?: {
    prismaClient?: IPrismaConsentClient;
    auditLogger?: AuditLogger;
  }) {
    this.prisma = options?.prismaClient;
    this.auditLogger = options?.auditLogger;
  }

  /**
   * Hashes client IP for privacy preservation.
   */
  private hashIp(ip?: string): string {
    const raw = ip?.trim() || 'UNKNOWN_IP';
    return crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
  }

  /**
   * Records affirmative consent for a specific consent type and version.
   */
  public async grantConsent(params: RecordConsentParams): Promise<ConsentRecord> {
    ConsentTypeSchema.parse(params.consentType);
    z.string().uuid().parse(params.userId);

    const now = Math.floor(Date.now() / 1000);
    const ipHash = this.hashIp(params.rawIpAddress);

    // If an existing consent for this type is active, withdraw it first (version upgrade)
    await this.withdrawConsent(params.userId, params.consentType, 'SUPERSEDED_BY_NEW_VERSION');

    const record: ConsentRecord = {
      id: crypto.randomUUID(),
      userId: params.userId,
      consentType: params.consentType,
      version: params.version,
      grantedAt: now,
      withdrawnAt: null,
      ipAddressHash: ipHash,
      metadata: params.metadata || {},
    };

    if (this.prisma) {
      await this.prisma.userConsent.create({ data: record });
    } else {
      this.inMemoryStore.set(record.id, record);
    }

    if (this.auditLogger) {
      await this.auditLogger.log({
        actorId: params.userId,
        actorRole: 'user',
        action: 'SETTINGS_CHANGE',
        resourceType: 'CONSENT',
        resourceId: `${params.consentType}:${params.version}`,
        rawIpAddress: params.rawIpAddress,
        outcome: 'success',
        metadata: {
          consentType: params.consentType,
          version: params.version,
          action: 'GRANTED',
        },
      });
    }

    return record;
  }

  /**
   * Withdraws consent with immediate effect.
   *
   * @param userId - User UUID
   * @param consentType - The consent category being revoked
   * @param reason - Optional audit note for the withdrawal
   */
  public async withdrawConsent(
    userId: string,
    consentType: ConsentType,
    reason: string = 'USER_INITIATED'
  ): Promise<boolean> {
    const now = Math.floor(Date.now() / 1000);
    let changed = false;

    if (this.prisma) {
      const result = await this.prisma.userConsent.updateMany({
        where: { userId, consentType, withdrawnAt: null },
        data: { withdrawnAt: now },
      });
      changed = result.count > 0;
    } else {
      for (const record of this.inMemoryStore.values()) {
        if (record.userId === userId && record.consentType === consentType && record.withdrawnAt === null) {
          record.withdrawnAt = now;
          changed = true;
        }
      }
    }

    if (changed && this.auditLogger) {
      await this.auditLogger.log({
        actorId: userId,
        actorRole: 'user',
        action: 'SETTINGS_CHANGE',
        resourceType: 'CONSENT',
        resourceId: consentType,
        outcome: 'success',
        metadata: {
          consentType,
          action: 'WITHDRAWN',
          reason,
        },
      });
    }

    return changed;
  }

  /**
   * Checks whether a user currently holds active and valid consent for an operation.
   * Also verifies if the stored consent matches current legal policy version.
   */
  public async checkConsent(userId: string, consentType: ConsentType): Promise<ConsentStatusResult> {
    const requiredVersion = ACTIVE_POLICY_VERSIONS[consentType];

    let activeRecord: ConsentRecord | null = null;

    if (this.prisma) {
      activeRecord = await this.prisma.userConsent.findFirst({
        where: {
          userId,
          consentType,
          withdrawnAt: null,
        },
        orderBy: { grantedAt: 'desc' },
      });
    } else {
      const records = Array.from(this.inMemoryStore.values()).filter(
        (r) => r.userId === userId && r.consentType === consentType && r.withdrawnAt === null
      );
      if (records.length > 0) {
        records.sort((a, b) => b.grantedAt - a.grantedAt);
        activeRecord = records[0] ?? null;
      }
    }

    if (!activeRecord) {
      return {
        hasConsent: false,
        requiresRePrompt: true,
        currentActiveVersion: requiredVersion,
      };
    }

    const isCurrentVersion = activeRecord.version === requiredVersion;

    return {
      hasConsent: true,
      version: activeRecord.version,
      requiresRePrompt: !isCurrentVersion,
      currentActiveVersion: requiredVersion,
    };
  }

  /**
   * Mandates explicit AI Processing consent before passing content to external models.
   * Throws an error if consent has not been granted.
   */
  public async requireAiConsent(userId: string): Promise<void> {
    const status = await this.checkConsent(userId, 'AI_PROCESSING');
    if (!status.hasConsent) {
      throw new Error(
        'DPDP_CONSENT_REQUIRED: Processing requires explicit consent for AI model analysis.'
      );
    }
  }

  /**
   * Exports all consent records for a user for regulatory disclosure or DPDP compliance.
   */
  public async exportUserConsentHistory(userId: string): Promise<ConsentRecord[]> {
    if (this.prisma) {
      return this.prisma.userConsent.findMany({
        where: { userId },
        orderBy: { grantedAt: 'desc' },
      });
    }

    return Array.from(this.inMemoryStore.values())
      .filter((r) => r.userId === userId)
      .sort((a, b) => b.grantedAt - a.grantedAt);
  }
}
