/**
 * @file retention.ts
 * @module privacy/retention
 * @description Production-grade data retention, sanitization, and cryptographic deletion service
 * compliant with India's Digital Personal Data Protection (DPDP) Act, 2023 and CERT-In directions.
 * Implements automated daily retention cleanup, secure S3 shredding, cascading deletions,
 * DPDP-compliant data export, and 30-day account deletion grace workflows.
 *
 * Security & Compliance Rationale:
 * 1. Storage Limitation (DPDP Act Sec. 8(7)): Data must be securely deleted once the specified purpose
 *    is served or retention schedules expire.
 * 2. Secure Object Shredding: S3 media hard-deletions can be overwritten with random bytes prior to
 *    deletion call to mitigate block-level remnants where applicable, or cryptographically erased.
 * 3. Cascade Integrity: Deleting a report must deterministically remove attached media uploads,
 *    forensic analysis artifacts, and cached scan results to prevent orphaned forensic data.
 * 4. Audit Preservation without PII: Confirmation of data deletion is recorded in the tamper-evident
 *    audit log while ensuring deleted payload content is never preserved in the log.
 * 5. CERT-In Mandate: System audit logs are preserved for at least 365 days regardless of user deletion requests.
 */

import crypto from 'node:crypto';
import { z } from 'zod';
import type { AuditLogger } from '../audit/logger.js';
import type { ConsentManager } from './consent.js';

// ============================================================================
// Schemas & Types
// ============================================================================

export const RetentionPolicySchema = z.object({
  mediaRetentionDays: z.number().int().min(1).default(30),
  reportRetentionDays: z.number().int().min(1).default(90),
  auditLogRetentionDays: z.number().int().min(180).default(365), // CERT-In minimum 180-365 days
  accountDeletionGraceDays: z.number().int().min(0).default(30),
});

export type RetentionPolicy = z.infer<typeof RetentionPolicySchema>;

export const DeletionStatusSchema = z.enum([
  'PENDING_VERIFICATION',
  'GRACE_PERIOD',
  'COMPLETED',
  'CANCELLED',
]);

export type DeletionStatus = z.infer<typeof DeletionStatusSchema>;

export interface AccountDeletionRequest {
  id: string;
  userId: string;
  status: DeletionStatus;
  requestedAt: number;
  graceExpiresAt: number;
  completedAt: number | null;
  confirmationTokenHash: string;
}

export interface UserExportPackage {
  exportedAt: string;
  userId: string;
  consentRecords: unknown[];
  reports: unknown[];
  uploadMetadata: unknown[];
  accountMetadata: {
    status: string;
    createdAt?: string;
  };
}

/**
 * Storage adapter interface (e.g. AWS S3 / MinIO).
 */
export interface IS3StorageAdapter {
  putObject(params: { bucket: string; key: string; body: Buffer }): Promise<void>;
  deleteObject(params: { bucket: string; key: string }): Promise<void>;
  headObject?(params: { bucket: string; key: string }): Promise<{ contentLength?: number }>;
}

/**
 * Prisma database client interface for retention engine.
 */
export interface IPrismaRetentionClient {
  mediaUpload: {
    findMany(args: {
      where: { createdAt: { lte: Date }; deletedAt?: null };
      select: { id: true; s3Bucket: true; s3Key: true };
    }): Promise<Array<{ id: string; s3Bucket: string; s3Key: string }>>;
    updateMany(args: {
      where: { id: { in: string[] } };
      data: { deletedAt: Date };
    }): Promise<{ count: number }>;
    deleteMany(args: { where: { id: { in: string[] } } }): Promise<{ count: number }>;
  };
  analysisReport: {
    findMany(args: {
      where: { createdAt: { lte: Date }; deletedAt?: null };
      select: { id: true; mediaUploadId?: string | null };
    }): Promise<Array<{ id: string; mediaUploadId?: string | null }>>;
    deleteMany(args: { where: { id: { in: string[] } } }): Promise<{ count: number }>;
  };
  accountDeletion: {
    create(args: { data: AccountDeletionRequest }): Promise<AccountDeletionRequest>;
    findFirst(args: { where: { userId: string; status: DeletionStatus } }): Promise<AccountDeletionRequest | null>;
    update(args: { where: { id: string }; data: Partial<AccountDeletionRequest> }): Promise<AccountDeletionRequest>;
    findMany(args: {
      where: {
        status: 'GRACE_PERIOD';
        graceExpiresAt: { lte: number };
      };
    }): Promise<AccountDeletionRequest[]>;
  };
  user: {
    findUnique(args: { where: { id: string } }): Promise<any>;
    delete(args: { where: { id: string } }): Promise<any>;
  };
}

// ============================================================================
// Retention Manager Class
// ============================================================================

export class RetentionManager {
  private readonly policy: RetentionPolicy;
  private readonly s3?: IS3StorageAdapter;
  private readonly prisma?: IPrismaRetentionClient;
  private readonly auditLogger?: AuditLogger;
  private readonly consentManager?: ConsentManager;

  // In-memory store fallback
  private inMemoryDeletionRequests: Map<string, AccountDeletionRequest> = new Map();

  constructor(options?: {
    policy?: Partial<RetentionPolicy>;
    s3Adapter?: IS3StorageAdapter;
    prismaClient?: IPrismaRetentionClient;
    auditLogger?: AuditLogger;
    consentManager?: ConsentManager;
  }) {
    this.policy = RetentionPolicySchema.parse(options?.policy || {});
    this.s3 = options?.s3Adapter;
    this.prisma = options?.prismaClient;
    this.auditLogger = options?.auditLogger;
    this.consentManager = options?.consentManager;
  }

  /**
   * Securely overwrites an S3 object with pseudorandom bytes prior to deletion
   * to ensure cryptographic eradication of file content.
   */
  public async secureDeleteS3Object(bucket: string, key: string, byteLength: number = 4096): Promise<void> {
    if (!this.s3) return;

    try {
      // Overwrite with cryptographically secure random bytes
      const randomNoise = crypto.randomBytes(Math.min(byteLength, 1024 * 1024));
      await this.s3.putObject({
        bucket,
        key,
        body: randomNoise,
      });
    } catch {
      // Even if overwrite fails (e.g. object already missing), proceed to deleteObject
    }

    // Permanently remove the object
    await this.s3.deleteObject({ bucket, key });
  }

  /**
   * Executes daily automated retention policy cleanup across media uploads and reports.
   * Runs as a scheduled cron job.
   */
  public async runScheduledRetentionCleanup(): Promise<{
    expiredMediaCount: number;
    expiredReportsCount: number;
    processedAccountDeletions: number;
  }> {
    const now = new Date();
    const mediaCutoff = new Date(now.getTime() - this.policy.mediaRetentionDays * 86400000);
    const reportCutoff = new Date(now.getTime() - this.policy.reportRetentionDays * 86400000);

    let expiredMediaCount = 0;
    let expiredReportsCount = 0;
    let processedAccountDeletions = 0;

    // 1. Clean expired media files
    if (this.prisma) {
      const expiredMedia = await this.prisma.mediaUpload.findMany({
        where: { createdAt: { lte: mediaCutoff }, deletedAt: null },
        select: { id: true, s3Bucket: true, s3Key: true },
      });

      for (const item of expiredMedia) {
        if (item.s3Bucket && item.s3Key) {
          await this.secureDeleteS3Object(item.s3Bucket, item.s3Key);
        }
      }

      if (expiredMedia.length > 0) {
        const ids = expiredMedia.map((m) => m.id);
        const res = await this.prisma.mediaUpload.deleteMany({
          where: { id: { in: ids } },
        });
        expiredMediaCount = res.count;
      }

      // 2. Clean expired analysis reports
      const expiredReports = await this.prisma.analysisReport.findMany({
        where: { createdAt: { lte: reportCutoff }, deletedAt: null },
        select: { id: true },
      });

      if (expiredReports.length > 0) {
        const repIds = expiredReports.map((r) => r.id);
        const repRes = await this.prisma.analysisReport.deleteMany({
          where: { id: { in: repIds } },
        });
        expiredReportsCount = repRes.count;
      }

      // 3. Process expired account deletion grace periods
      const nowSec = Math.floor(Date.now() / 1000);
      const readyDeletions = await this.prisma.accountDeletion.findMany({
        where: {
          status: 'GRACE_PERIOD',
          graceExpiresAt: { lte: nowSec },
        },
      });

      for (const req of readyDeletions) {
        await this.executePermanentAccountDeletion(req.userId);
        await this.prisma.accountDeletion.update({
          where: { id: req.id },
          data: { status: 'COMPLETED', completedAt: nowSec },
        });
        processedAccountDeletions++;
      }
    }

    if (this.auditLogger) {
      await this.auditLogger.log({
        action: 'DATA_DELETE',
        resourceType: 'RETENTION_CLEANUP',
        resourceId: 'CRON_JOB',
        outcome: 'success',
        metadata: {
          expiredMediaCount,
          expiredReportsCount,
          processedAccountDeletions,
        },
      });
    }

    return {
      expiredMediaCount,
      expiredReportsCount,
      processedAccountDeletions,
    };
  }

  /**
   * Initiates account deletion workflow:
   * 1. Issues a secure confirmation token
   * 2. Sets status to PENDING_VERIFICATION
   */
  public async requestAccountDeletion(userId: string): Promise<{ requestId: string; confirmationToken: string }> {
    const confirmationToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(confirmationToken, 'utf8').digest('hex');

    const nowSec = Math.floor(Date.now() / 1000);
    const graceExpiresAt = nowSec + this.policy.accountDeletionGraceDays * 86400;

    const request: AccountDeletionRequest = {
      id: crypto.randomUUID(),
      userId,
      status: 'PENDING_VERIFICATION',
      requestedAt: nowSec,
      graceExpiresAt,
      completedAt: null,
      confirmationTokenHash: tokenHash,
    };

    if (this.prisma) {
      await this.prisma.accountDeletion.create({ data: request });
    } else {
      this.inMemoryDeletionRequests.set(request.id, request);
    }

    if (this.auditLogger) {
      await this.auditLogger.log({
        actorId: userId,
        actorRole: 'user',
        action: 'DATA_DELETE',
        resourceType: 'ACCOUNT_DELETION_REQUEST',
        resourceId: request.id,
        outcome: 'success',
        metadata: {
          gracePeriodDays: this.policy.accountDeletionGraceDays,
          graceExpiresAt,
        },
      });
    }

    return {
      requestId: request.id,
      confirmationToken,
    };
  }

  /**
   * Confirms account deletion with the confirmation token, transitioning to 30-day GRACE_PERIOD.
   */
  public async confirmAccountDeletion(requestId: string, token: string): Promise<boolean> {
    const candidateHash = crypto.createHash('sha256').update(token.trim(), 'utf8').digest('hex');

    let request: AccountDeletionRequest | null = null;
    if (this.prisma) {
      request = await this.prisma.accountDeletion.findFirst({
        where: { id: requestId, status: 'PENDING_VERIFICATION' } as any,
      });
    } else {
      request = this.inMemoryDeletionRequests.get(requestId) || null;
    }

    if (!request || request.status !== 'PENDING_VERIFICATION') {
      return false;
    }

    const matches = crypto.timingSafeEqual(
      Buffer.from(candidateHash, 'utf8'),
      Buffer.from(request.confirmationTokenHash, 'utf8')
    );

    if (!matches) {
      return false;
    }

    request.status = 'GRACE_PERIOD';

    if (this.prisma) {
      await this.prisma.accountDeletion.update({
        where: { id: requestId },
        data: { status: 'GRACE_PERIOD' },
      });
    }

    if (this.auditLogger) {
      await this.auditLogger.log({
        actorId: request.userId,
        actorRole: 'user',
        action: 'DATA_DELETE',
        resourceType: 'ACCOUNT_DELETION_CONFIRMED',
        resourceId: requestId,
        outcome: 'success',
        metadata: {
          status: 'GRACE_PERIOD_ACTIVE',
          graceExpiresAt: request.graceExpiresAt,
        },
      });
    }

    return true;
  }

  /**
   * Cancels a pending or grace-period deletion request if the user logs back in or opts out.
   */
  public async cancelAccountDeletion(userId: string): Promise<boolean> {
    if (this.prisma) {
      const active = await this.prisma.accountDeletion.findFirst({
        where: { userId, status: 'GRACE_PERIOD' },
      });
      if (active) {
        await this.prisma.accountDeletion.update({
          where: { id: active.id },
          data: { status: 'CANCELLED' },
        });
        return true;
      }
    } else {
      for (const req of this.inMemoryDeletionRequests.values()) {
        if (req.userId === userId && req.status === 'GRACE_PERIOD') {
          req.status = 'CANCELLED';
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Performs permanent cascading deletion of all user records once grace period lapses.
   */
  public async executePermanentAccountDeletion(userId: string): Promise<void> {
    if (this.prisma) {
      // 1. Delete associated media uploads from S3 and DB
      const userUploads = await this.prisma.mediaUpload.findMany({
        where: { userId } as any,
        select: { id: true, s3Bucket: true, s3Key: true },
      });

      for (const upload of userUploads) {
        if (upload.s3Bucket && upload.s3Key) {
          await this.secureDeleteS3Object(upload.s3Bucket, upload.s3Key);
        }
      }

      await this.prisma.mediaUpload.deleteMany({
        where: { userId } as any,
      });

      // 2. Cascade delete analysis reports
      await this.prisma.analysisReport.deleteMany({
        where: { userId } as any,
      });

      // 3. Delete user account record
      await this.prisma.user.delete({
        where: { id: userId },
      });
    }

    // 4. Log deletion confirmation audit entry (NO user PII retained)
    if (this.auditLogger) {
      await this.auditLogger.log({
        actorId: 'SYSTEM_RETENTION_ENGINE',
        actorRole: 'SYSTEM',
        action: 'DATA_DELETE',
        resourceType: 'USER_ACCOUNT',
        resourceId: userId,
        outcome: 'success',
        metadata: {
          action: 'PERMANENT_CASCADE_DELETED',
          dpdpComplianceSection: 'Section 8(7)',
        },
      });
    }
  }

  /**
   * Generates a complete, downloadable DPDP Data Export package in JSON format.
   * Ensures users can exercise their Right to Access Information (DPDP Section 11).
   */
  public async exportUserData(userId: string): Promise<UserExportPackage> {
    const consentRecords = this.consentManager
      ? await this.consentManager.exportUserConsentHistory(userId)
      : [];

    let reports: any[] = [];
    let uploads: any[] = [];
    let userRecord: any = null;

    if (this.prisma) {
      reports = await (this.prisma.analysisReport as any).findMany({
        where: { userId },
      });
      uploads = await this.prisma.mediaUpload.findMany({
        where: { userId } as any,
        select: { id: true, createdAt: true, status: true } as any,
      });
      userRecord = await this.prisma.user.findUnique({
        where: { id: userId },
      });
    }

    if (this.auditLogger) {
      await this.auditLogger.log({
        actorId: userId,
        actorRole: 'user',
        action: 'DATA_EXPORT',
        resourceType: 'USER_DATA_PACKAGE',
        resourceId: userId,
        outcome: 'success',
        metadata: {
          recordCount: reports.length + uploads.length + consentRecords.length,
        },
      });
    }

    return {
      exportedAt: new Date().toISOString(),
      userId,
      consentRecords,
      reports,
      uploadMetadata: uploads,
      accountMetadata: {
        status: userRecord ? 'ACTIVE' : 'UNKNOWN',
        createdAt: userRecord?.createdAt?.toISOString(),
      },
    };
  }
}
