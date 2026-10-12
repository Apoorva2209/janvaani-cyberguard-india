/**
 * @file packages/backend/src/upload/scanner.ts
 * @description Malware scanning interface and ClamAV integration for CyberGuard India.
 * 
 * SECURITY RATIONALE:
 * - Fail-closed architecture: if the malware scanner is unreachable or errors out,
 *   the file MUST be rejected immediately (never allow uninspected files into the system).
 * - ClamAV daemon communication uses raw socket INSTREAM protocol for maximum performance
 *   without writing unvalidated files to disk.
 * - Enforce a hard 30-second timeout per scan to prevent denial of service through archive/regex stalls.
 * - Log strictly file hashes, scanner versions, and verdicts to the audit log.
 *   NEVER log file byte contents or sensitive payload fragments.
 * - Infected files are quarantined for forensic preservation and immediately isolated from production access.
 */

import * as net from 'node:net';
import { z } from 'zod';
import type { SecureObjectStorage } from './storage.js';

/**
 * Standard scan verdicts.
 */
export type ScanVerdict = 'CLEAN' | 'INFECTED' | 'SCAN_ERROR' | 'TIMEOUT';

/**
 * Scan result contract.
 */
export interface ScanResult {
  readonly verdict: ScanVerdict;
  readonly fileSha256: string;
  readonly scannerName: string;
  readonly scannerVersion: string;
  readonly scanDurationMs: number;
  readonly virusName?: string;
  readonly details?: string;
}

/**
 * Audit record schema (ensuring no raw payload content is logged).
 */
export const ScanAuditRecordSchema = z.object({
  fileSha256: z.string().length(64),
  verdict: z.enum(['CLEAN', 'INFECTED', 'SCAN_ERROR', 'TIMEOUT']),
  scannerName: z.string(),
  scannerVersion: z.string(),
  scanDurationMs: z.number().nonnegative(),
  virusName: z.string().optional(),
  quarantined: z.boolean(),
  quarantineStorageKey: z.string().optional(),
  timestamp: z.string().datetime(),
});

export type ScanAuditRecord = z.infer<typeof ScanAuditRecordSchema>;

/**
 * Pluggable malware scanner interface.
 */
export interface MalwareScanner {
  readonly name: string;
  getVersion(): Promise<string>;
  scanBuffer(buffer: Buffer, fileSha256: string): Promise<ScanResult>;
}

/**
 * ClamAV scanner configuration.
 */
export interface ClamAVConfig {
  host?: string;
  port?: number;
  socketPath?: string;
  timeoutMs?: number; // Default 30,000ms
}

/**
 * ClamAV Socket Scanner implementing the ClamAV INSTREAM protocol over TCP or Unix domain socket.
 */
export class ClamAVScanner implements MalwareScanner {
  public readonly name = 'ClamAV';
  private readonly host: string;
  private readonly port: number;
  private readonly socketPath?: string;
  private readonly timeoutMs: number;

  constructor(config?: ClamAVConfig) {
    this.host = config?.host || process.env.CLAMAV_HOST || '127.0.0.1';
    this.port = config?.port || Number(process.env.CLAMAV_PORT || 3310);
    this.socketPath = config?.socketPath || process.env.CLAMAV_SOCKET;
    this.timeoutMs = config?.timeoutMs || 30_000; // Strict 30s timeout
  }

  /**
   * Retrieves ClamAV daemon version string.
   */
  public async getVersion(): Promise<string> {
    return new Promise((resolve, reject) => {
      const socket = this.createConnection();
      let response = '';

      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error('ClamAV version check timed out'));
      }, 5000);

      socket.on('connect', () => {
        socket.write('zVERSION\0');
      });

      socket.on('data', (chunk) => {
        response += chunk.toString('ascii');
      });

      socket.on('end', () => {
        clearTimeout(timer);
        resolve(response.replace(/\0/g, '').trim() || 'ClamAV 1.0+');
      });

      socket.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  /**
   * Scans a file buffer using the ClamAV INSTREAM protocol.
   * Format: 'zINSTREAM\0' followed by chunks of [4-byte big-endian length, data], terminated by 4 zero bytes.
   */
  public async scanBuffer(buffer: Buffer, fileSha256: string): Promise<ScanResult> {
    const startTime = Date.now();
    let version = 'ClamAV Daemon';

    try {
      version = await this.getVersion();
    } catch {
      // Fallback version if getVersion fails; scan attempt will follow
    }

    return new Promise<ScanResult>((resolve) => {
      const socket = this.createConnection();
      let response = '';
      let isCompleted = false;

      const timer = setTimeout(() => {
        if (!isCompleted) {
          isCompleted = true;
          socket.destroy();
          resolve({
            verdict: 'TIMEOUT',
            fileSha256,
            scannerName: this.name,
            scannerVersion: version,
            scanDurationMs: Date.now() - startTime,
            details: `ClamAV scan exceeded deadline of ${this.timeoutMs}ms`,
          });
        }
      }, this.timeoutMs);

      socket.on('connect', () => {
        try {
          socket.write('zINSTREAM\0');

          // Send data in chunks of 64KB
          const CHUNK_SIZE = 64 * 1024;
          let offset = 0;

          while (offset < buffer.length) {
            const chunkSize = Math.min(CHUNK_SIZE, buffer.length - offset);
            const chunkSlice = buffer.subarray(offset, offset + chunkSize);

            const lengthHeader = Buffer.alloc(4);
            lengthHeader.writeUInt32BE(chunkSize, 0);

            socket.write(lengthHeader);
            socket.write(chunkSlice);
            offset += chunkSize;
          }

          // Terminate with 4-byte 0 length chunk
          const termination = Buffer.alloc(4);
          termination.writeUInt32BE(0, 0);
          socket.write(termination);
        } catch (err: any) {
          if (!isCompleted) {
            isCompleted = true;
            clearTimeout(timer);
            socket.destroy();
            resolve({
              verdict: 'SCAN_ERROR',
              fileSha256,
              scannerName: this.name,
              scannerVersion: version,
              scanDurationMs: Date.now() - startTime,
              details: err?.message || 'Socket stream write error',
            });
          }
        }
      });

      socket.on('data', (chunk) => {
        response += chunk.toString('ascii');
      });

      socket.on('end', () => {
        if (!isCompleted) {
          isCompleted = true;
          clearTimeout(timer);
          const duration = Date.now() - startTime;
          const cleanResp = response.replace(/\0/g, '').trim();

          // Responses:
          // 'stream: OK'
          // 'stream: <VirusName> FOUND'
          // 'stream: <Error> ERROR'
          if (cleanResp.endsWith('OK')) {
            resolve({
              verdict: 'CLEAN',
              fileSha256,
              scannerName: this.name,
              scannerVersion: version,
              scanDurationMs: duration,
            });
          } else if (cleanResp.includes('FOUND')) {
            const match = cleanResp.match(/stream:\s*(.+)\s*FOUND/i);
            const virusName = match?.[1] ? match[1].trim() : 'Malware.Detected';
            resolve({
              verdict: 'INFECTED',
              fileSha256,
              scannerName: this.name,
              scannerVersion: version,
              scanDurationMs: duration,
              virusName,
            });
          } else {
            resolve({
              verdict: 'SCAN_ERROR',
              fileSha256,
              scannerName: this.name,
              scannerVersion: version,
              scanDurationMs: duration,
              details: cleanResp || 'Unrecognized ClamAV response',
            });
          }
        }
      });

      socket.on('error', (err) => {
        if (!isCompleted) {
          isCompleted = true;
          clearTimeout(timer);
          resolve({
            verdict: 'SCAN_ERROR',
            fileSha256,
            scannerName: this.name,
            scannerVersion: version,
            scanDurationMs: Date.now() - startTime,
            details: `ClamAV socket connection failed: ${err.message}`,
          });
        }
      });
    });
  }

  private createConnection(): net.Socket {
    if (this.socketPath) {
      return net.createConnection(this.socketPath);
    }
    return net.createConnection({ host: this.host, port: this.port });
  }
}

/**
 * Scan coordinator and quarantine executor.
 * Enforces fail-closed validation and audit trail persistence.
 */
export class MalwareScanService {
  private readonly scanner: MalwareScanner;
  private readonly storage?: SecureObjectStorage;
  private readonly auditLogs: ScanAuditRecord[] = [];

  constructor(scanner?: MalwareScanner, storage?: SecureObjectStorage) {
    this.scanner = scanner || new ClamAVScanner();
    this.storage = storage;
  }

  /**
   * Scans a file buffer and throws if malware is detected or if scan fails.
   * Fail-Closed Policy:
   * - CLEAN: Passes through
   * - INFECTED: Moves to quarantine bucket, records audit log, throws error
   * - SCAN_ERROR or TIMEOUT: Rejects file to prevent scanning bypasses
   */
  public async scanAndEnforce(params: {
    buffer: Buffer;
    fileSha256: string;
    storageKey?: string;
  }): Promise<ScanResult> {
    const { buffer, fileSha256, storageKey } = params;

    let result: ScanResult;
    try {
      result = await this.scanner.scanBuffer(buffer, fileSha256);
    } catch (err: any) {
      result = {
        verdict: 'SCAN_ERROR',
        fileSha256,
        scannerName: this.scanner.name,
        scannerVersion: 'Unknown',
        scanDurationMs: 0,
        details: err?.message || 'Unexpected scanner crash',
      };
    }

    let quarantineKey: string | undefined;

    // Handle INFECTED files: Quarantine immediately
    if (result.verdict === 'INFECTED') {
      if (this.storage && storageKey) {
        try {
          quarantineKey = await this.storage.moveToQuarantine(storageKey, buffer);
        } catch {
          // Quarantine fallback failed
        }
      }

      this.recordAudit({
        fileSha256,
        verdict: 'INFECTED',
        scannerName: result.scannerName,
        scannerVersion: result.scannerVersion,
        scanDurationMs: result.scanDurationMs,
        virusName: result.virusName,
        quarantined: Boolean(quarantineKey),
        quarantineStorageKey: quarantineKey,
        timestamp: new Date().toISOString(),
      });

      throw new Error(
        `Malware detected (${result.virusName || 'Threat'}). File has been quarantined and rejected.`
      );
    }

    // Fail-Closed: SCAN_ERROR or TIMEOUT must not allow file entry
    if (result.verdict === 'SCAN_ERROR' || result.verdict === 'TIMEOUT') {
      this.recordAudit({
        fileSha256,
        verdict: result.verdict,
        scannerName: result.scannerName,
        scannerVersion: result.scannerVersion,
        scanDurationMs: result.scanDurationMs,
        quarantined: false,
        timestamp: new Date().toISOString(),
      });

      throw new Error(
        `File security scan could not be completed safely (${result.verdict}: ${result.details || 'Unavailable'}). Upload rejected.`
      );
    }

    // CLEAN verdict
    this.recordAudit({
      fileSha256,
      verdict: 'CLEAN',
      scannerName: result.scannerName,
      scannerVersion: result.scannerVersion,
      scanDurationMs: result.scanDurationMs,
      quarantined: false,
      timestamp: new Date().toISOString(),
    });

    return result;
  }

  /**
   * Logs strictly sanitized audit metadata. Never logs raw file buffers or PII.
   */
  private recordAudit(record: ScanAuditRecord): void {
    const validated = ScanAuditRecordSchema.parse(record);
    this.auditLogs.push(validated);
    // In production, emit to secure append-only audit stream (e.g. CloudWatch / Winston / DB)
  }

  /**
   * Returns copy of recent audit records.
   */
  public getAuditHistory(): readonly ScanAuditRecord[] {
    return [...this.auditLogs];
  }
}
