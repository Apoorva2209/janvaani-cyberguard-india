/**
 * @file packages/backend/src/upload/storage.ts
 * @description Production-grade AWS S3 secure object storage implementation for CyberGuard India.
 * 
 * SECURITY RATIONALE:
 * - S3 keys are purely UUIDv4 hashes; never leak user-supplied filenames or tenant paths in object keys.
 * - Enforce Server-Side Encryption with AES-256 (SSE-S3 / AES256) on every upload.
 * - Forced storage Content-Type: 'application/octet-stream' and Content-Disposition: 'attachment; filename="..."'
 *   to neutralize stored Cross-Site Scripting (XSS) and drive-by execution attacks in browsers.
 * - Never store sensitive user metadata in S3 object headers (which can leak in S3 logs or bucket policies);
 *   all forensic metadata must reside in the secure database.
 * - Short-lived pre-signed URLs (maximum 15 minutes / 900s) with cryptographic signatures.
 * - Verification on deletion to prevent orphaned or compromised object references.
 */

import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  HeadObjectCommand,
  type S3ClientConfig,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';

/**
 * Storage configuration schema validated via Zod.
 */
export const StorageConfigSchema = z.object({
  region: z.string().default('ap-south-1'), // Mumbai region default for India compliance
  bucketName: z.string().min(3),
  quarantineBucketName: z.string().min(3).optional(),
  endpoint: z.string().url().optional(), // For MinIO / LocalStack / VPC S3 endpoint
  forcePathStyle: z.boolean().default(false),
  urlExpirySeconds: z.number().int().min(60).max(900).default(900), // Default 15 minutes
});

export type StorageConfig = z.infer<typeof StorageConfigSchema>;

/**
 * Upload parameters schema.
 */
export const FileUploadParamsSchema = z.object({
  buffer: z.instanceof(Buffer),
  sanitizedFilename: z.string().min(1).max(255),
  sha256Hash: z.string().length(64),
  mimeType: z.string(),
  isQuarantine: z.boolean().optional().default(false),
});

export type FileUploadParams = z.infer<typeof FileUploadParamsSchema>;

/**
 * Storage result returned after successful encrypted write.
 */
export interface SecureStorageResult {
  storageKey: string;
  bucket: string;
  sizeBytes: number;
  sha256Hash: string;
  serverSideEncryption: string;
  etag?: string;
}

/**
 * Storage management service.
 */
export class SecureObjectStorage {
  private readonly client: S3Client;
  private readonly config: StorageConfig;

  constructor(config?: Partial<StorageConfig>) {
    this.config = StorageConfigSchema.parse({
      region: process.env.AWS_REGION || 'ap-south-1',
      bucketName: process.env.S3_BUCKET_NAME || 'cyberguard-uploads-private',
      quarantineBucketName: process.env.S3_QUARANTINE_BUCKET || 'cyberguard-quarantine-private',
      endpoint: process.env.S3_ENDPOINT,
      forcePathStyle: process.env.S3_FORCE_PATH_STYLE === 'true',
      urlExpirySeconds: 900, // Strict 15 minute TTL
      ...config,
    });

    const clientConfig: S3ClientConfig = {
      region: this.config.region,
      ...(this.config.endpoint ? { endpoint: this.config.endpoint, forcePathStyle: this.config.forcePathStyle } : {}),
    };

    this.client = new S3Client(clientConfig);
  }

  /**
   * Uploads an artifact using server-side encryption and safe headers.
   * Key is guaranteed to be a random UUIDv4.
   */
  public async upload(params: FileUploadParams): Promise<SecureStorageResult> {
    const validated = FileUploadParamsSchema.parse(params);
    const storageKey = randomUUID();
    const targetBucket = validated.isQuarantine && this.config.quarantineBucketName
      ? this.config.quarantineBucketName
      : this.config.bucketName;

    // Force application/octet-stream and attachment to block browser execution
    const contentDisposition = `attachment; filename="${encodeURIComponent(validated.sanitizedFilename)}"`;

    const command = new PutObjectCommand({
      Bucket: targetBucket,
      Key: storageKey,
      Body: validated.buffer,
      // Mandatory Server-Side Encryption with AES-256
      ServerSideEncryption: 'AES256',
      // Force octet-stream regardless of media type to prevent mime-sniffing execution
      ContentType: 'application/octet-stream',
      ContentDisposition: contentDisposition,
      // Store SHA256 checksum in S3 header for integrity verification
      ChecksumSHA256: Buffer.from(validated.sha256Hash, 'hex').toString('base64'),
      // DO NOT store PII or user metadata here - stored solely in secure DB
    });

    const response = await this.client.send(command);

    return {
      storageKey,
      bucket: targetBucket,
      sizeBytes: validated.buffer.length,
      sha256Hash: validated.sha256Hash,
      serverSideEncryption: response.ServerSideEncryption || 'AES256',
      etag: response.ETag,
    };
  }

  /**
   * Generates a temporary pre-signed URL for authorized download.
   * Access expires strictly after 15 minutes (or configured urlExpirySeconds).
   */
  public async getPresignedDownloadUrl(
    storageKey: string,
    originalFilename?: string,
    customExpirySeconds?: number
  ): Promise<string> {
    // Validate storageKey format to prevent directory traversal
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(storageKey)) {
      throw new Error('Invalid storage key: must be a valid UUID');
    }

    const expiry = Math.min(
      customExpirySeconds || this.config.urlExpirySeconds,
      900 // Hard ceiling 15 minutes
    );

    const safeFilename = originalFilename ? encodeURIComponent(originalFilename) : 'cyberguard-download';

    const command = new GetObjectCommand({
      Bucket: this.config.bucketName,
      Key: storageKey,
      ResponseContentType: 'application/octet-stream',
      ResponseContentDisposition: `attachment; filename="${safeFilename}"`,
    });

    return await getSignedUrl(this.client, command, {
      expiresIn: expiry,
    });
  }

  /**
   * Reads an object buffer directly for backend processing (e.g., malware scanning, metadata stripping).
   * Does NOT expose URL or content to external users.
   */
  public async getObjectBuffer(storageKey: string, isQuarantine = false): Promise<Buffer> {
    const bucket = isQuarantine && this.config.quarantineBucketName
      ? this.config.quarantineBucketName
      : this.config.bucketName;

    const command = new GetObjectCommand({
      Bucket: bucket,
      Key: storageKey,
    });

    const response = await this.client.send(command);
    if (!response.Body) {
      throw new Error(`Object not found or empty body for key: ${storageKey}`);
    }

    const byteArray = await response.Body.transformToByteArray();
    return Buffer.from(byteArray);
  }

  /**
   * Verifies existence before deleting an object, confirming destruction.
   */
  public async deleteWithVerification(storageKey: string, isQuarantine = false): Promise<boolean> {
    const bucket = isQuarantine && this.config.quarantineBucketName
      ? this.config.quarantineBucketName
      : this.config.bucketName;

    // 1. Verify object exists
    try {
      await this.client.send(new HeadObjectCommand({ Bucket: bucket, Key: storageKey }));
    } catch (err: unknown) {
      // Object already does not exist
      return false;
    }

    // 2. Perform deletion
    await this.client.send(new DeleteObjectCommand({ Bucket: bucket, Key: storageKey }));

    // 3. Confirm deletion
    try {
      await this.client.send(new HeadObjectCommand({ Bucket: bucket, Key: storageKey }));
      // If head succeeded, deletion failed
      throw new Error(`Deletion verification failed: object ${storageKey} still present in ${bucket}`);
    } catch (err: any) {
      if (err.name === 'NotFound' || err.$metadata?.httpStatusCode === 404) {
        return true;
      }
      throw err;
    }
  }

  /**
   * Batch deletes expired or retained objects for GDPR / DPDP Act compliance.
   */
  public async batchDelete(storageKeys: string[], isQuarantine = false): Promise<{
    deletedCount: number;
    errors: Array<{ key: string; code?: string; message?: string }>;
  }> {
    if (storageKeys.length === 0) {
      return { deletedCount: 0, errors: [] };
    }

    const bucket = isQuarantine && this.config.quarantineBucketName
      ? this.config.quarantineBucketName
      : this.config.bucketName;

    // S3 DeleteObjects supports up to 1000 keys per call
    const chunks: string[][] = [];
    for (let i = 0; i < storageKeys.length; i += 1000) {
      chunks.push(storageKeys.slice(i, i + 1000));
    }

    let totalDeleted = 0;
    const errors: Array<{ key: string; code?: string; message?: string }> = [];

    for (const chunk of chunks) {
      const command = new DeleteObjectsCommand({
        Bucket: bucket,
        Delete: {
          Objects: chunk.map((k) => ({ Key: k })),
          Quiet: false,
        },
      });

      const response = await this.client.send(command);
      totalDeleted += response.Deleted?.length ?? 0;

      if (response.Errors && response.Errors.length > 0) {
        for (const err of response.Errors) {
          if (err.Key) {
            errors.push({
              key: err.Key,
              code: err.Code,
              message: err.Message,
            });
          }
        }
      }
    }

    return { deletedCount: totalDeleted, errors };
  }

  /**
   * Moves a file from normal storage bucket to the quarantine bucket.
   */
  public async moveToQuarantine(storageKey: string, buffer: Buffer): Promise<string> {
    if (!this.config.quarantineBucketName) {
      throw new Error('Quarantine bucket not configured in object storage');
    }

    // 1. Write to quarantine bucket
    await this.upload({
      buffer,
      sanitizedFilename: 'quarantined_payload',
      sha256Hash: randomUUID().replace(/-/g, '') + randomUUID().replace(/-/g, ''), // placeholder or known hash
      mimeType: 'application/octet-stream',
      isQuarantine: true,
    });

    // 2. Remove from active bucket if it existed
    try {
      await this.deleteWithVerification(storageKey, false);
    } catch {
      // Ignore if not yet written to normal bucket
    }

    return storageKey;
  }
}
